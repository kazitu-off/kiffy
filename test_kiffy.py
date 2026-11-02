#!/usr/bin/env python3
"""End-to-end tests for the Kiffy v2 server: TCP chat, HTTP, WebSocket.

Runs the server as a subprocess on a test port, then exercises the protocol.
Usage: python3 test_kiffy.py
"""

import asyncio
import base64
import hashlib
import json
import os
import signal
import struct
import subprocess
import sys
import time
import urllib.request

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

PORT = int(os.environ.get("KIFFY_TEST_PORT", 8899))
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}  {detail}")


class TcpChat:
    def __init__(self):
        self.reader = self.writer = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", PORT)

    async def send(self, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode()
        self.writer.write(len(payload).to_bytes(4, "big") + payload)
        await self.writer.drain()

    async def recv(self, timeout=3):
        try:
            header = await asyncio.wait_for(self.reader.readexactly(4), timeout)
            payload = await asyncio.wait_for(
                self.reader.readexactly(int.from_bytes(header, "big")), timeout)
            return json.loads(payload)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, json.JSONDecodeError):
            return None

    async def close(self):
        self.writer.close()


class WsChat:
    def __init__(self):
        self.reader = self.writer = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", PORT)
        key = base64.b64encode(os.urandom(16)).decode()
        self.writer.write((
            f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())
        await self.writer.drain()
        resp = await asyncio.wait_for(self.reader.readuntil(b"\r\n\r\n"), 3)
        assert b"101" in resp.split(b"\r\n")[0], resp
        expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        assert expected.encode() in resp, "bad Sec-WebSocket-Accept"

    async def send(self, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode()
        mask = os.urandom(4)
        n = len(payload)
        head = bytearray((0x81,))
        if n < 126:
            head.append(0x80 | n)
        elif n < 65536:
            head += bytes((0x80 | 126,)) + n.to_bytes(2, "big")
        else:
            head += bytes((0x80 | 127,)) + n.to_bytes(8, "big")
        rep = (mask * (n // 4 + 1))[:n]
        masked = (int.from_bytes(payload, "big") ^ int.from_bytes(rep, "big")).to_bytes(n, "big") if n else b""
        self.writer.write(bytes(head) + mask + masked)
        await self.writer.drain()

    async def recv(self, timeout=3):
        """Returns ('text', obj) / ('close', None); skips ping/pong."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                head = await asyncio.wait_for(self.reader.readexactly(2), deadline - time.monotonic())
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                return None
            op = head[0] & 0x0F
            size = head[1] & 0x7F
            if size == 126:
                size = int.from_bytes(await self.reader.readexactly(2), "big")
            elif size == 127:
                size = int.from_bytes(await self.reader.readexactly(8), "big")
            data = await self.reader.readexactly(size) if size else b""
            if op == 0x8:
                return ("close", None)
            if op in (0x9, 0xA):
                continue
            return ("text", json.loads(data))
        return None

    async def close(self):
        self.writer.close()


async def wait_for(t, pred, timeout=3, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        msgs = [t.__class__] and None
        # pull until predicate matches or timeout
        while True:
            pass
    return None


async def drain_until(sock, t_type, timeout=3, field=None, value=None):
    """Read messages until one of type t_type (optionally matching field) arrives."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = await sock.recv(max(0.05, end - time.monotonic()))
        if r is None:
            return None
        kind, m = r
        if kind == "close":
            return ("close", None)
        if m.get("t") == t_type and (field is None or m.get(field) == value):
            return m
    return None


async def tcp_until(sock, t_type, timeout=3, field=None, value=None):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        m = await sock.recv(max(0.05, end - time.monotonic()))
        if m is None:
            return None
        if m.get("t") == t_type and (field is None or m.get(field) == value):
            return m
    return None


async def test_http():
    print("HTTP:")
    for path, expect in [("/", 200), ("/app.html", (200, 500)), ("/android.html", 200),
                         ("/kiffy_server.py", 200), ("/manifest.json", 200), ("/version", 200), ("/nope.html", 404)]:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=3) as r:
                check(f"GET {path} -> {r.status}", r.status in (expect if isinstance(expect, tuple) else (expect,)))
        except urllib.error.HTTPError as e:
            check(f"GET {path} -> {e.code}", e.code in (expect if isinstance(expect, tuple) else (expect,)))


async def test_tcp():
    print("TCP chat:")
    alice, bob = TcpChat(), TcpChat()
    await alice.connect()
    await bob.connect()

    # hello / welcome
    await alice.send({"t": "hello", "v": 2, "user": "alice"})
    w = await tcp_until(alice, "welcome")
    check("alice welcome", w is not None and w.get("user") == "alice", str(w))
    check("alice history list", isinstance(w.get("history"), list))

    await bob.send({"t": "hello", "v": 2, "user": "bob"})
    await tcp_until(bob, "welcome")
    join = await tcp_until(alice, "sys", field="text", value="bob joined (2 online)")
    check("join broadcast", join is not None)
    users = await tcp_until(alice, "users")
    check("users broadcast on join", users is not None and len(users.get("users", [])) == 2)

    # duplicate name rejected
    eve = TcpChat()
    await eve.connect()
    await eve.send({"t": "hello", "v": 2, "user": "alice"})
    e = await tcp_until(eve, "error")
    check("duplicate name rejected", e is not None and "taken" in e.get("msg", ""), str(e))
    await eve.close()

    # invalid name rejected
    await eve.connect()
    await eve.send({"t": "hello", "v": 2, "user": "x!"})
    e = await tcp_until(eve, "error")
    check("invalid name rejected", e is not None, str(e))
    await eve.close()

    # public message
    await bob.send({"t": "msg", "text": "hello alice"})
    m = await tcp_until(alice, "msg", field="from", value="bob")
    check("public message", m is not None and m["text"] == "hello alice", str(m))

    # pm
    await bob.send({"t": "pm", "to": "alice", "text": "psst"})
    pm = await tcp_until(alice, "pm", field="from", value="bob")
    ack = await tcp_until(bob, "pm_sent")
    check("pm delivery", pm is not None and pm["text"] == "psst", str(pm))
    check("pm ack to sender", ack is not None)

    # slash-command pm via msg
    await bob.send({"t": "msg", "text": "/s alice via-slash"})
    pm = await tcp_until(alice, "pm", field="text", value="via-slash")
    check("slash /s pm", pm is not None)

    # ping/pong
    await bob.send({"t": "ping", "ts": 12345})
    p = await tcp_until(bob, "pong")
    check("ping/pong", p is not None and p.get("ts") == 12345)

    # typing
    await bob.send({"t": "typing", "on": True})
    ty = await tcp_until(alice, "typing", field="user", value="bob")
    check("typing relay", ty is not None and ty.get("on") is True)

    # users command
    await bob.send({"t": "users"})
    u = await tcp_until(bob, "users")
    check("/users", u is not None and len(u["users"]) == 2)

    # history contains the public message
    await alice.send({"t": "exit"})
    await alice.close()

    carol = TcpChat()
    await carol.connect()
    await carol.send({"t": "hello", "v": 2, "user": "carol"})
    w = await tcp_until(carol, "welcome")
    texts = [h.get("text") for h in w.get("history", [])]
    check("history replay", "hello alice" in texts, str(texts))

    # admin flow: password required then granted
    adm = TcpChat()
    await adm.connect()
    await adm.send({"t": "hello", "v": 2, "user": "admin"})
    pw = await tcp_until(adm, "pw")
    check("admin pw prompt", pw is not None)
    await adm.send({"t": "auth", "pw": "secret"})
    w = await tcp_until(adm, "welcome")
    check("admin welcome", w is not None and w.get("admin") is True, str(w))

    # wrong admin password
    adm2 = TcpChat()
    await adm2.connect()
    await adm2.send({"t": "hello", "v": 2, "user": "admin"})
    await tcp_until(adm2, "pw")
    await adm2.send({"t": "auth", "pw": "wrong"})
    e = await tcp_until(adm2, "error")
    check("wrong admin pw rejected", e is not None)
    await adm2.close()

    # admin global + star + ban
    await adm.send({"t": "msg", "text": "/global attention everyone"})
    g = await tcp_until(bob, "global")
    check("/global broadcast", g is not None and g["text"] == "attention everyone")

    await adm.send({"t": "msg", "text": "/star carol"})
    s = await tcp_until(carol, "sys", field="text", value="⭐ carol received the Kiffy Star")
    check("/star", s is not None)

    m = await tcp_until(bob, "msg")
    # carol says something -> bob should see star flag
    await carol.send({"t": "msg", "text": "am i starred?"})
    m = await tcp_until(bob, "msg", field="from", value="carol")
    check("star flag in messages", m is not None and m.get("star") is True, str(m))

    await adm.send({"t": "msg", "text": "/ban carol spam"})
    left = await tcp_until(bob, "sys", field="text", value="carol was banned (reason: spam)")
    check("/ban broadcast", left is not None)

    # banned name cannot rejoin
    await carol.close()
    carol2 = TcpChat()
    await carol2.connect()
    await carol2.send({"t": "hello", "v": 2, "user": "carol"})
    e = await tcp_until(carol2, "error", field="msg", value="You are banned from this server.")
    check("banned name rejected", e is not None)
    await carol2.close()

    # unban clears the name and its captured IP (so later tests can connect)
    await adm.send({"t": "msg", "text": "/unban carol"})
    u = await tcp_until(adm, "sys", field="text", value="carol unbanned.")
    check("/unban", u is not None)
    again = TcpChat()
    await again.connect()
    await again.send({"t": "hello", "v": 2, "user": "carol"})
    w2 = await tcp_until(again, "welcome")
    check("rejoin after unban", w2 is not None)
    await again.send({"t": "exit"})
    await again.close()

    for s in (bob, adm):
        await s.send({"t": "exit"})
        await s.close()


async def test_ws():
    print("WebSocket:")
    wa, wb = WsChat(), WsChat()
    await wa.connect()
    await wb.connect()
    await wa.send({"t": "hello", "v": 2, "user": "wsalice"})
    w = await drain_until(wa, "welcome")
    check("ws welcome", w is not None and w.get("user") == "wsalice", str(w))
    await wb.send({"t": "hello", "v": 2, "user": "wsbob"})
    await drain_until(wb, "welcome")

    await wb.send({"t": "msg", "text": "hi over websocket"})
    m = await drain_until(wa, "msg", field="from", value="wsbob")
    check("ws message relay", m is not None and m["text"] == "hi over websocket", str(m))

    # tcp <-> ws interop
    tc = TcpChat()
    await tc.connect()
    await tc.send({"t": "hello", "v": 2, "user": "tcpguy"})
    await tcp_until(tc, "welcome")
    await tc.send({"t": "msg", "text": "tcp -> ws"})
    m = await drain_until(wa, "msg", field="from", value="tcpguy")
    check("tcp->ws interop", m is not None and m["text"] == "tcp -> ws", str(m))

    await wa.send({"t": "msg", "text": "ws -> tcp"})
    m = await tcp_until(tc, "msg", field="from", value="wsalice")
    check("ws->tcp interop", m is not None and m["text"] == "ws -> tcp", str(m))

    for s in (wa, wb, tc):
        try:
            await s.send({"t": "exit"})
        except Exception:
            pass
        await s.close()


async def main():
    env = dict(os.environ, KIFFY_ADMIN_PASSWORD="secret", KIFFY_PORT=str(PORT))
    proc = subprocess.Popen(
        [sys.executable, "kiffy_server.py"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=os.path.dirname(os.path.abspath(__file__)))
    await asyncio.sleep(1.5)
    try:
        await test_http()
        await test_tcp()
        await test_ws()
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        print("--- server output ---")
        print(out.decode(errors="replace")[-3000:])
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    asyncio.run(main())
