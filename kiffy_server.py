#!/usr/bin/env python3
"""
Kiffy v2 — async messenger server. Standard library only, no dependencies.

One port (default 8888) carries three protocols, auto-detected per connection:

  * TCP chat  — 4-byte big-endian length + JSON frame  (terminal clients)
  * HTTP/1.1  — static files (web app, landing page, downloads)
  * WebSocket — /ws endpoint                           (Material You web app)

Wire protocol v2 (JSON objects, field "t" is the message type):

  client -> server
    {"t":"hello","v":2,"user":"name","pw":...,"proof":...}   first message
    {"t":"auth","pw":"..."}          admin password (if server asks {"t":"pw"})
    {"t":"msg","text":"..."}         public message / slash command
    {"t":"pm","to":"name","text":"..."}
    {"t":"anchor","to":"name"} / {"t":"unanchor"}
    {"t":"users"}                    request user list
    {"t":"typing","on":true|false}
    {"t":"ping","ts":123}            replied with {"t":"pong","ts":123}
    {"t":"exit"}

  server -> client
    {"t":"nonce","nonce":"hex"}      PSK mode only, before hello (unencrypted)
    {"t":"pw"}                       admin password required
    {"t":"welcome","user":..,"admin":..,"users":[..],"history":[..],"psk":..}
    {"t":"error","msg":"..."}
    {"t":"msg","from":..,"text":..,"ts":..,"star":..}
    {"t":"pm","from":..,"text":..,"ts":..}   / {"t":"pm_sent","to":..}
    {"t":"global","from":..,"text":..,"ts":..}
    {"t":"sys","text":..,"ts":..}
    {"t":"users","users":[{"n":name,"s":star,"a":admin},..]}
    {"t":"typing","user":..,"on":..}
    {"t":"pong","ts":..}

Optional transport encryption: run `python kiffy_server.py --psk <passphrase>`
(requires the `cryptography` package). The passphrase itself never crosses the
wire: the client proves knowledge of it with HMAC-SHA256 over a server nonce
and both sides derive the same session key. With one shared session key a
broadcast is encrypted ONCE and written N times.

Scaling notes versus v1 (thread-per-client):
  * one event loop instead of one thread per connection,
  * length-prefixed framing (v1 read raw recv() and could split/merge messages),
  * broadcasts never block on slow clients (per-peer write buffers + kick),
  * token-bucket rate limiter (O(1)) instead of rebuilding timestamp lists,
  * all state lives on the event loop thread -> no locks anywhere.
"""

import argparse
import asyncio
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import time
from collections import deque

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

MAX_FRAME = 64 * 1024          # hard cap for one wire frame
MAX_TEXT = 16 * 1024           # cap for user-visible text
HISTORY_LIMIT = 100            # messages kept in RAM
HISTORY_SEND = 30              # messages replayed on join
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
NAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
RATE_CAP = 30                  # burst
RATE_PER_SEC = 30 / 60         # sustained messages per second

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.html": ("app.html", "text/html; charset=utf-8"),
    "/android.html": ("android.html", "text/html; charset=utf-8"),
    "/kiffy_server.py": ("kiffy_server.py", "text/plain; charset=utf-8"),
    "/kiffy_client.py": ("kiffy_client.py", "text/plain; charset=utf-8"),
    "/mobile_host.py": ("mobile_host.py", "text/plain; charset=utf-8"),
    "/manifest.json": ("manifest.json", "application/manifest+json; charset=utf-8"),
    "/sw.js": ("sw.js", "application/javascript; charset=utf-8"),
    "/version": ("version.json", "application/json; charset=utf-8"),
    "/version.json": ("version.json", "application/json; charset=utf-8"),
    "/LICENSE": ("LICENSE", "text/plain; charset=utf-8"),
    "/windows.zip": ("windows.zip", "application/zip"),
    "/kiffy-mobile.zip": ("kiffy-mobile.zip", "application/zip"),
    "/kiffy.apk": ("kiffy.apk", "application/vnd.android.package-archive"),
}


def now():
    return int(time.time())


def jdump(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()


class ExitChat(Exception):
    pass


class Bucket:
    """Token bucket, O(1) per check."""

    __slots__ = ("tokens", "ts")

    def __init__(self):
        self.tokens = float(RATE_CAP)
        self.ts = time.monotonic()

    def allow(self):
        t = time.monotonic()
        self.tokens = min(RATE_CAP, self.tokens + (t - self.ts) * RATE_PER_SEC)
        self.ts = t
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


# --------------------------------------------------------------------------
# Peers: one class per transport, shared chat logic in KiffyServer.chat_session
# --------------------------------------------------------------------------

class Peer:
    def __init__(self, server, reader, writer):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.name = None
        self.admin = False
        self.anchor = None
        self.enc = False
        self.alive = True
        addr = writer.get_extra_info("peername")
        self.ip = addr[0] if addr else "?"

    def close(self):
        self.alive = False
        try:
            self.writer.close()
        except Exception:
            pass

    def _write(self, framed):
        if not self.alive:
            raise ConnectionError("peer closed")
        self.writer.write(framed)
        if self.writer.transport.get_write_buffer_size() > 2_000_000:
            raise ConnectionError("peer too slow")

    @staticmethod
    def frame(payload):
        """Transport-specific framing of an (already encrypted) payload."""
        raise NotImplementedError

    def send(self, obj):
        """Serialize (and encrypt, in PSK mode) once, frame, write."""
        payload = jdump(obj)
        if self.enc and self.server.cipher:
            payload = self.server.cipher.encrypt(payload)
        self._write(self.frame(payload))

    def safe_error(self, msg):
        try:
            self.send({"t": "error", "msg": msg})
        except Exception:
            pass
        self.close()

    async def recv(self):
        raise NotImplementedError


class TCPPeer(Peer):
    """4-byte big-endian length prefix + payload.

    The first byte of the prefix doubles as the protocol marker (always 0x00,
    which no HTTP method starts with); handle_conn consumes it to pick the
    transport and hands it back here so the length stays 4 bytes on the wire.
    """

    def __init__(self, server, reader, writer, first_byte=b"\x00"):
        super().__init__(server, reader, writer)
        self._header0 = first_byte

    @staticmethod
    def frame(payload):
        return len(payload).to_bytes(4, "big") + payload

    async def recv(self):
        try:
            if self._header0 is not None:
                # first frame: the demux already consumed its first header byte
                rest = await self.reader.readexactly(3)
                size = int.from_bytes(self._header0 + rest, "big")
                self._header0 = None
            else:
                size = int.from_bytes(await self.reader.readexactly(4), "big")
            if size == 0 or size > MAX_FRAME:
                return None
            payload = await self.reader.readexactly(size)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            return None
        if self.enc and self.server.cipher:
            try:
                payload = self.server.cipher.decrypt(payload)
            except Exception:
                return None
        try:
            obj = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return obj if isinstance(obj, dict) else None


class WSPeer(Peer):
    """RFC 6455 server side: JSON over text frames, pings answered inline."""

    @staticmethod
    def frame(payload):
        n = len(payload)
        if n < 126:
            head = bytes((0x81, n))
        elif n < 65536:
            head = bytes((0x81, 126)) + n.to_bytes(2, "big")
        else:
            head = bytes((0x81, 127)) + n.to_bytes(8, "big")
        return head + payload

    def _write_control(self, payload, op):
        head = bytes((0x80 | op, len(payload)))
        self._write(head + payload)

    async def _read_frame(self):
        head = await self.reader.readexactly(2)
        fin, op = head[0] & 0x80, head[0] & 0x0F
        masked, size = head[1] & 0x80, head[1] & 0x7F
        if size == 126:
            size = int.from_bytes(await self.reader.readexactly(2), "big")
        elif size == 127:
            size = int.from_bytes(await self.reader.readexactly(8), "big")
        if size > MAX_FRAME:
            raise ConnectionError("ws frame too large")
        mask = await self.reader.readexactly(4) if masked else None
        data = await self.reader.readexactly(size) if size else b""
        if mask and data:
            rep = (mask * (len(data) // 4 + 1))[: len(data)]
            data = (int.from_bytes(data, "big") ^ int.from_bytes(rep, "big")).to_bytes(len(data), "big")
        return fin, op, data

    async def recv(self):
        buf = b""
        while True:
            try:
                fin, op, data = await self._read_frame()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                return None
            if op == 0x8:                                   # close
                try:
                    self._write_control(data[:2], 0x8)
                except Exception:
                    pass
                return None
            if op == 0x9:                                   # ping
                try:
                    self._write_control(data, 0xA)
                except Exception:
                    pass
                continue
            if op == 0xA:                                   # pong
                continue
            if op in (0x1, 0x2):
                buf = data
                if fin:
                    return self._decode(buf)
            elif op == 0x0:
                buf += data
                if fin:
                    return self._decode(buf)
            else:
                return None

    @staticmethod
    def _decode(buf):
        try:
            obj = json.loads(buf.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return obj if isinstance(obj, dict) else None


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------

class KiffyServer:
    def __init__(self, host="0.0.0.0", port=8888, psk=None, admin_password=None):
        self.host = host
        self.port = port
        self.psk = psk
        self.admin_password = admin_password
        self.cipher = None
        self.nonce = secrets.token_hex(16)

        self.clients = {}            # name -> Peer
        self.starred = set()
        self.admins = set()
        self.bans = {}               # name -> {"ip": str, "reason": str}
        self.global_emoji = "\U0001F4E2"                  # 📢
        self.typing = {}             # name -> expiry (monotonic)
        self.msg_buckets = {}        # "name|ip" -> Bucket
        self.conn_buckets = {}       # ip -> Bucket
        self.history = deque(maxlen=HISTORY_LIMIT)

    # -- rate limiting ------------------------------------------------------

    def _bucket(self, store, key):
        b = store.get(key)
        if b is None:
            b = store[key] = Bucket()
        return b

    def allow_connect(self, ip):
        return self._bucket(self.conn_buckets, ip).allow()

    def allow_message(self, name, ip):
        return self._bucket(self.msg_buckets, f"{name}|{ip}").allow()

    def prune_buckets(self):
        stale = time.monotonic() - 600
        for store in (self.msg_buckets, self.conn_buckets):
            for k in [k for k, b in store.items() if b.ts < stale]:
                del store[k]

    # -- helpers ------------------------------------------------------------

    def log(self, text):
        print(f"[{time.strftime('%H:%M:%S')}] {text}", flush=True)

    def record(self, obj):
        self.history.append(obj)

    def broadcast(self, obj, exclude=None):
        """Serialize/encrypt/frame ONCE per transport, write N times.
        Never blocks on slow peers — oversized write buffers get kicked."""
        payload = jdump(obj)
        if self.cipher:
            payload = self.cipher.encrypt(payload)
        framed_tcp = TCPPeer.frame(payload)
        framed_ws = WSPeer.frame(payload)
        dead = []
        for name, peer in list(self.clients.items()):
            if name == exclude:
                continue
            try:
                peer._write(framed_tcp if isinstance(peer, TCPPeer) else framed_ws)
            except Exception:
                dead.append(name)
        for name in dead:
            self.drop(name, quiet=True)

    def broadcast_users(self):
        self.broadcast({"t": "users", "users": self.users_payload()})

    def users_payload(self):
        return [
            {"n": n, "s": n in self.starred, "a": n in self.admins}
            for n in self.clients
        ]

    def is_banned(self, name, ip):
        if name in self.bans:
            return True
        return any(b["ip"] == ip for b in self.bans.values())

    def drop(self, name, quiet=False):
        peer = self.clients.pop(name, None)
        if peer is None:
            return
        peer.close()
        self.typing.pop(name, None)
        self.starred.discard(name)
        self.admins.discard(name)
        if not quiet:
            self.log(f"{name} left ({len(self.clients)} online)")
            self.system(f"{name} left ({len(self.clients)} online)")
        self.broadcast_users()

    def system(self, text):
        obj = {"t": "sys", "text": text, "ts": now()}
        self.record(obj)
        self.broadcast(obj)

    def local_ips(self):
        ips = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
            s.close()
        except OSError:
            pass
        try:
            for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
                if ip not in ips and ip != "127.0.0.1":
                    ips.append(ip)
        except OSError:
            pass
        return ips or ["127.0.0.1"]

    # -- admin actions ------------------------------------------------------

    def ban(self, target, reason):
        peer = self.clients.get(target)
        if peer is None:
            return False
        self.bans[target] = {"ip": peer.ip, "reason": reason}
        try:
            peer.send({"t": "sys", "text": f"You are banned. Reason: {reason}", "ts": now()})
        except Exception:
            pass
        self.drop(target, quiet=True)
        self.system(f"{target} was banned (reason: {reason})")
        return True

    # -- chat session (shared by TCP and WS) ----------------------------------

    async def chat_session(self, peer):
        # Always speak first so clients can detect plain/PSK mode without guessing.
        if self.cipher:
            peer.send({"t": "nonce", "nonce": self.nonce})
        else:
            peer.send({"t": "hi", "psk": False})

        obj = await peer.recv()
        if not obj or obj.get("t") != "hello" or obj.get("v") != 2:
            peer.safe_error("This is a Kiffy v2 server — update your client.")
            return
        if self.cipher:
            proof = str(obj.get("proof") or "")
            expected = hmac.new(self.psk.encode(), self.nonce.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, proof):
                peer.safe_error("Wrong passphrase.")
                return
            peer.enc = True

        name = str(obj.get("user", "")).strip()
        if not NAME_RE.match(name):
            peer.safe_error("Invalid username: 3-20 chars, letters/digits/_")
            return
        if self.is_banned(name, peer.ip):
            peer.safe_error("You are banned from this server.")
            return

        is_admin = False
        if name == "admin" and self.admin_password:
            pw = str(obj.get("pw") or "")
            if not pw:
                peer.send({"t": "pw"})
                obj2 = await peer.recv()
                pw = str(obj2.get("pw") or "") if obj2 else ""
            if not hmac.compare_digest(pw.encode(), self.admin_password.encode()):
                peer.safe_error("Wrong admin password.")
                return
            is_admin = True

        if name in self.clients:
            peer.safe_error("Username already taken.")
            return

        # register (no awaits between the last check and here -> race-free)
        peer.name = name
        peer.admin = is_admin
        if is_admin:
            self.admins.add(name)
        self.clients[name] = peer

        peer.send({
            "t": "welcome", "user": name, "admin": is_admin,
            "users": self.users_payload(), "history": list(self.history)[-HISTORY_SEND:],
            "psk": bool(self.cipher),
        })
        self.log(f"{name} joined ({len(self.clients)} online) from {peer.ip}")
        self.system(f"{name} joined ({len(self.clients)} online)")
        self.broadcast_users()

        try:
            await self.chat_loop(peer)
        except ExitChat:
            pass
        finally:
            if peer.name:
                self.drop(peer.name)

    async def chat_loop(self, peer):
        while True:
            obj = await peer.recv()
            if obj is None:
                return
            t = obj.get("t")

            if t == "ping":
                peer.send({"t": "pong", "ts": obj.get("ts")})
            elif t == "msg":
                if not self.allow_message(peer.name, peer.ip):
                    peer.send({"t": "error", "msg": "Rate limit: max 30 messages per minute."})
                    continue
                text = str(obj.get("text", ""))
                if text.startswith("/"):
                    if not self.handle_command(peer, text):
                        return          # /exit
                else:
                    await self.public_message(peer, text)
            elif t == "pm":
                if not self.allow_message(peer.name, peer.ip):
                    peer.send({"t": "error", "msg": "Rate limit: max 30 messages per minute."})
                    continue
                await self.private_message(peer, str(obj.get("to", "")), str(obj.get("text", "")))
            elif t == "anchor":
                target = str(obj.get("to", ""))
                if target in self.clients and target != peer.name:
                    peer.anchor = target
                    peer.send({"t": "sys", "text": f"Anchored to {target}. All messages go to them.", "ts": now()})
                else:
                    peer.send({"t": "error", "msg": f"User {target} not found."})
            elif t == "unanchor":
                peer.anchor = None
                peer.send({"t": "sys", "text": "Anchor removed.", "ts": now()})
            elif t == "users":
                peer.send({"t": "users", "users": self.users_payload()})
            elif t == "typing":
                self.set_typing(peer.name, bool(obj.get("on")))
            elif t == "exit":
                return
            # unknown types are ignored (forward compatibility)

    def set_typing(self, name, on):
        if on:
            self.typing[name] = time.monotonic() + 5
            self.broadcast({"t": "typing", "user": name, "on": True}, exclude=name)
        elif name in self.typing:
            del self.typing[name]
            self.broadcast({"t": "typing", "user": name, "on": False}, exclude=name)

    async def public_message(self, peer, text):
        text = text.strip()[:MAX_TEXT]
        if not text:
            return
        if peer.name in self.typing:
            del self.typing[peer.name]
            self.broadcast({"t": "typing", "user": peer.name, "on": False}, exclude=peer.name)
        obj = {"t": "msg", "from": peer.name, "text": text, "ts": now(),
               "star": peer.name in self.starred}
        self.record(obj)
        self.broadcast(obj, exclude=peer.name)

    async def private_message(self, peer, target, text):
        text = text.strip()[:MAX_TEXT]
        if not text:
            return
        if peer.anchor and not target:
            target = peer.anchor
        tp = self.clients.get(target)
        if tp is None:
            peer.send({"t": "error", "msg": f"User {target} is not online."})
            return
        try:
            tp.send({"t": "pm", "from": peer.name, "text": text, "ts": now()})
        except Exception:
            peer.send({"t": "error", "msg": f"User {target} is not reachable."})
            return
        peer.send({"t": "pm_sent", "to": target})

    def handle_command(self, peer, text):
        """Slash commands (keeps the terminal client dumb). Returns False on /exit."""
        cmd, _, rest = text.partition(" ")
        cmd = cmd.lower()
        rest = rest.strip()

        if cmd == "/exit":
            return False
        if cmd == "/help":
            lines = ["Commands: /users /s [user] [msg] /anchor [user] /unanchor /exit"]
            if peer.admin:
                lines.append("Admin: /star /unstar /global /setemoji /makeadmin /removeadmin /ban /unban /banlist")
            peer.send({"t": "sys", "text": "\n".join(lines), "ts": now()})
        elif cmd == "/users":
            peer.send({"t": "sys", "text": "Online: " + ", ".join(self.clients), "ts": now()})
        elif cmd == "/s":
            target, _, msg = rest.partition(" ")
            asyncio.get_running_loop().create_task(
                self.private_message(peer, target.strip(), msg))
        elif cmd == "/anchor":
            if rest in self.clients and rest != peer.name:
                peer.anchor = rest
                peer.send({"t": "sys", "text": f"Anchored to {rest}.", "ts": now()})
            else:
                peer.send({"t": "error", "msg": f"User {rest} not found."})
        elif cmd == "/unanchor":
            peer.anchor = None
            peer.send({"t": "sys", "text": "Anchor removed.", "ts": now()})
        elif cmd == "/star" and peer.admin:
            if rest in self.clients:
                self.starred.add(rest)
                peer.send({"t": "sys", "text": f"Star given to {rest}.", "ts": now()})
                self.system(f"⭐ {rest} received the Kiffy Star")
            else:
                peer.send({"t": "error", "msg": f"User {rest} not found."})
        elif cmd == "/unstar" and peer.admin:
            self.starred.discard(rest)
            peer.send({"t": "sys", "text": f"Star removed from {rest}.", "ts": now()})
        elif cmd == "/global" and peer.admin:
            if rest:
                obj = {"t": "global", "from": peer.name, "text": rest[:MAX_TEXT], "ts": now()}
                self.record(obj)
                self.broadcast(obj)
        elif cmd == "/setemoji" and peer.admin and rest:
            self.global_emoji = rest[:8]
        elif cmd == "/makeadmin" and peer.admin:
            tp = self.clients.get(rest)
            if tp:
                tp.admin = True
                self.admins.add(rest)
                self.system(f"{rest} is now an admin")
            else:
                peer.send({"t": "error", "msg": f"User {rest} not found."})
        elif cmd == "/removeadmin" and peer.admin:
            tp = self.clients.get(rest)
            if rest == "admin":
                peer.send({"t": "error", "msg": "Cannot remove the main admin."})
            elif tp:
                tp.admin = False
                self.admins.discard(rest)
            else:
                peer.send({"t": "error", "msg": f"User {rest} not found."})
        elif cmd == "/ban" and peer.admin:
            target, _, reason = rest.partition(" ")
            if target == "admin":
                peer.send({"t": "error", "msg": "Cannot ban the main admin."})
            elif not self.ban(target, reason.strip() or "No reason"):
                peer.send({"t": "error", "msg": f"User {target} not found."})
        elif cmd == "/unban" and peer.admin:
            if rest in self.bans:
                del self.bans[rest]     # clears the name and the IP captured with it
                peer.send({"t": "sys", "text": f"{rest} unbanned.", "ts": now()})
            else:
                peer.send({"t": "error", "msg": f"{rest} is not banned."})
        elif cmd == "/banlist" and peer.admin:
            peer.send({"t": "sys", "text": "Banned: " + (", ".join(sorted(self.bans)) or "no banned users"), "ts": now()})
        else:
            peer.send({"t": "error", "msg": "Unknown command. Try /help"})
        return True

    # -- typing sweeper ---------------------------------------------------------

    async def sweep(self):
        while True:
            await asyncio.sleep(2)
            expired = [n for n, exp in self.typing.items() if exp < time.monotonic()]
            for n in expired:
                self.typing.pop(n, None)
                self.broadcast({"t": "typing", "user": n, "on": False}, exclude=n)
            if int(time.time()) % 60 == 0:
                self.prune_buckets()

    # -- TCP / HTTP / WS demux ----------------------------------------------------

    async def handle_conn(self, reader, writer):
        try:
            first = await asyncio.wait_for(reader.readexactly(1), timeout=300)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            writer.close()
            return

        if first == b"\x00":                      # framed TCP chat client
            peer = TCPPeer(self, reader, writer, first_byte=first)
            if self.is_banned("", peer.ip):
                peer.safe_error("You are banned from this server.")
                writer.close()
                return
            if not self.allow_connect(peer.ip):
                writer.close()
                return
            try:
                await self.chat_session(peer)
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close()
            return

        await self.handle_http(reader, writer, first)

    # -- HTTP ----------------------------------------------------------------------

    async def handle_http(self, reader, writer, first_byte):
        buf = first_byte
        try:
            while True:
                try:
                    buf += await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
                except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                        asyncio.LimitOverrunError, ConnectionError, OSError):
                    break
                head = buf.decode("latin-1", "replace")
                buf = b""

                line, _, rest = head.partition("\r\n")
                parts = line.split(" ")
                if len(parts) != 3 or not parts[2].startswith("HTTP/"):
                    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    break
                method, raw_path, version = parts
                path = raw_path.split("?", 1)[0]

                headers = {}
                for h in rest.split("\r\n"):
                    if ":" in h:
                        k, _, v = h.partition(":")
                        headers[k.strip().lower()] = v.strip()

                if path == "/ws":
                    if "websocket" in headers.get("upgrade", "").lower() and headers.get("sec-websocket-key"):
                        await self.upgrade_ws(reader, writer, headers)
                    else:
                        writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
                                     b"Content-Length: 33\r\nConnection: close\r\n\r\n"
                                     b"WebSocket endpoint: use ws://host/ws\r\n")
                        await writer.drain()
                    break

                keep = version == "HTTP/1.1" and "close" not in headers.get("connection", "").lower()
                if method in ("GET", "HEAD"):
                    await self.serve_static(writer, path, method == "HEAD", keep)
                else:
                    body = b"405 - GET only"
                    writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\n"
                                 + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                                 + body)
                    await writer.drain()
                    break
                if not keep:
                    break
        finally:
            writer.close()

    async def serve_static(self, writer, path, head_only, keep):
        entry = STATIC_FILES.get(path)
        if entry is None:
            body = "404 — not found. Try / (landing) or /app.html (web app).".encode()
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\n"
                         + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
            await writer.drain()
            return
        fname, ctype = entry
        fpath = os.path.join(BASE_DIR, fname)
        try:
            size = os.path.getsize(fpath)
        except OSError:
            body = ("500 — server file missing: " + fname).encode()
            writer.write(b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain; charset=utf-8\r\n"
                         + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
            await writer.drain()
            return
        try:
            headers = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: {ctype}\r\n"
                f"Content-Length: {size}\r\n"
                f"Cache-Control: {'no-cache' if ctype.startswith('text/html') else 'max-age=3600'}\r\n"
                f"Connection: {'keep-alive' if keep else 'close'}\r\n\r\n"
            ).encode("latin-1")
            writer.write(headers)
            if not head_only:
                with open(fpath, "rb") as f:
                    while True:
                        chunk = f.read(262144)
                        if not chunk:
                            break
                        writer.write(chunk)
            await writer.drain()
        except (OSError, ConnectionError):
            writer.close()

    # -- WebSocket -------------------------------------------------------------------

    async def upgrade_ws(self, reader, writer, headers):
        key = headers["sec-websocket-key"]
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        writer.write(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode("latin-1")
        )
        await writer.drain()

        peer = WSPeer(self, reader, writer)
        try:
            await self.chat_session(peer)
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    # -- startup -----------------------------------------------------------------------

    def banner(self):
        print("\n  ⚡ KIFFY v2 SERVER")
        print("  " + "=" * 46)
        for ip in self.local_ips():
            print(f"    Web app   http://{ip}:{self.port}/app.html")
            print(f"    Landing   http://{ip}:{self.port}/")
        print(f"    Port      {self.port}  (chat + web + websocket)")
        print(f"    Encrypt   {'PSK (passphrase required)' if self.cipher else 'plain — start with --psk to encrypt'}")
        print(f"    Admin     {'password set via env/arg' if self.admin_password else 'login as username admin'}")
        print("  " + "=" * 46 + "\n")

    async def run(self):
        server = await asyncio.start_server(self.handle_conn, self.host, self.port, limit=1 << 20)
        sweeper = asyncio.create_task(self.sweep())
        self.banner()
        async with server:
            try:
                await server.serve_forever()
            finally:
                sweeper.cancel()


def main():
    ap = argparse.ArgumentParser(description="Kiffy v2 messenger server")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", os.environ.get("KIFFY_PORT", 8888))))
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--psk", default=os.environ.get("KIFFY_PSK"),
                    help="passphrase for encrypted transport (needs `cryptography`)")
    ap.add_argument("--admin-password", default=os.environ.get("KIFFY_ADMIN_PASSWORD"))
    args = ap.parse_args()

    # tunable rate limits (trusted LANs can raise them)
    global RATE_CAP, RATE_PER_SEC
    RATE_CAP = float(os.environ.get("KIFFY_RATE_CAP", RATE_CAP))
    RATE_PER_SEC = float(os.environ.get("KIFFY_RATE_PER_SEC", RATE_PER_SEC))

    admin_password = args.admin_password
    if not admin_password and sys.stdin.isatty():
        admin_password = getpass.getpass("Set admin password (username 'admin'): ")

    srv = KiffyServer(args.host, args.port, psk=args.psk, admin_password=admin_password)
    if args.psk:
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            print("error: --psk requires the `cryptography` package:  pip install cryptography", file=sys.stderr)
            sys.exit(1)
        # psk never crosses the wire; the per-run nonce keeps keys unique per start
        raw = hashlib.sha256((args.psk + "|" + srv.nonce).encode()).digest()
        srv.cipher = Fernet(base64.urlsafe_b64encode(raw))

    try:
        asyncio.run(srv.run())
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    main()
