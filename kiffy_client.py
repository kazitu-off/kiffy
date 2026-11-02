#!/usr/bin/env python3
"""
Kiffy v2 terminal client — asyncio, standard library only.

Talks the framed JSON protocol (see kiffy_server.py docstring). Pass the same
--psk passphrase the server was started with to enable encrypted transport
(requires the `cryptography` package on both ends).
"""

import argparse
import asyncio
import base64
import getpass
import hashlib
import hmac
import json
import sys
import time

MAX_FRAME = 64 * 1024


def c(code):
    return code if sys.stdout.isatty() else ""


DIM, RESET, BOLD = c("\x1b[2m"), c("\x1b[0m"), c("\x1b[1m")
GREEN, YELLOW, RED = c("\x1b[32m"), c("\x1b[33m"), c("\x1b[31m")


def ts(sec):
    return time.strftime("%H:%M", time.localtime(sec or time.time()))


class KiffyClient:
    def __init__(self, host, port, psk=None):
        self.host, self.port, self.psk = host, port, psk
        self.reader = self.writer = None
        self.name = None
        self.admin = False
        self.enc = False
        self.cipher = None

    # -- wire -------------------------------------------------------------------

    async def send(self, obj):
        payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
        if self.enc and self.cipher:
            payload = self.cipher.encrypt(payload)
        self.writer.write(len(payload).to_bytes(4, "big") + payload)
        await self.writer.drain()

    async def recv(self):
        try:
            header = await self.reader.readexactly(4)
            size = int.from_bytes(header, "big")
            if size == 0 or size > MAX_FRAME:
                return None
            payload = await self.reader.readexactly(size)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            return None
        if self.enc and self.cipher:
            try:
                payload = self.cipher.decrypt(payload)
            except Exception:
                return None
        try:
            obj = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return obj if isinstance(obj, dict) else None

    # -- session --------------------------------------------------------------------

    async def connect(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        except OSError as e:
            print(f"{RED}✗ Cannot reach {self.host}:{self.port} — {e}{RESET}")
            return False

        first = await self.recv()
        proof = None
        if not first:
            print(f"{RED}✗ Server closed the connection.{RESET}")
            return False
        if first.get("t") == "nonce":
            if not self.psk:
                print(f"{RED}✗ This server requires a passphrase (it runs with --psk).{RESET}")
                return False
            self._derive_cipher(first["nonce"])
            proof = hmac.new(self.psk.encode(), first["nonce"].encode(), hashlib.sha256).hexdigest()
        elif first.get("t") == "hi":
            if self.psk:
                print(f"{DIM}Server runs unencrypted — passphrase ignored.{RESET}")
                self.cipher = None

        await self.send({"t": "hello", "v": 2, "user": self.name, "proof": proof})
        self.enc = self.cipher is not None

        resp = await self.recv()
        if resp and resp.get("t") == "pw":
            pw = getpass.getpass("Admin password: ")
            await self.send({"t": "auth", "pw": pw})
            resp = await self.recv()
        if not resp:
            print(f"{RED}✗ Connection lost.{RESET}")
            return False
        if resp.get("t") == "error":
            print(f"{RED}✗ {resp.get('msg')}{RESET}")
            return False
        if resp.get("t") != "welcome":
            print(f"{RED}✗ Unexpected server response.{RESET}")
            return False

        self.admin = bool(resp.get("admin"))
        users = ", ".join(u["n"] for u in resp.get("users", []))
        print(f"{GREEN}✓ Connected as {BOLD}{self.name}{RESET}{GREEN}"
              f"{'  🌟 admin' if self.admin else ''} | online: {users}{RESET}")
        for m in resp.get("history", []):
            self.render(m, replay=True)
        return True

    def _derive_cipher(self, nonce):
        from cryptography.fernet import Fernet
        raw = hashlib.sha256((self.psk + "|" + nonce).encode()).digest()
        self.cipher = Fernet(base64.urlsafe_b64encode(raw))

    # -- rendering ----------------------------------------------------------------------

    def render(self, m, replay=False):
        t = m.get("t")
        tag = "" if replay else f"{DIM}{ts(m.get('ts'))}{RESET} "
        if t == "msg":
            star = "⭐" if m.get("star") else ""
            print(f"\r{tag}{star}{BOLD}{m['from']}{RESET}: {m['text']}")
        elif t == "pm":
            print(f"\r{tag}{YELLOW}🔒 [private] {BOLD}{m['from']}{RESET}{YELLOW}: {m['text']}{RESET}")
        elif t == "pm_sent":
            print(f"\r{DIM}→ to {m['to']}{RESET}")
        elif t == "global":
            print(f"\r{tag}{YELLOW}📢 [GLOBAL] {m['from']}: {m['text']}{RESET}")
        elif t == "sys":
            print(f"\r{tag}{DIM}{m['text']}{RESET}")
        elif t == "error":
            print(f"\r{RED}✗ {m.get('msg')}{RESET}")

    async def receiver(self):
        while True:
            m = await self.recv()
            if m is None:
                print(f"\r{DIM}— disconnected —{RESET}")
                return
            self.render(m)

    async def input_loop(self):
        loop = asyncio.get_running_loop()
        while True:
            line = await loop.run_in_executor(None, input, f"{BOLD}{self.name}>{RESET} ")
            line = line.strip()
            if not line:
                continue
            if line.lower() == "/exit":
                await self.send({"t": "exit"})
                return
            await self.send({"t": "msg", "text": line[:16384]})

    # -- main loop -------------------------------------------------------------------------

    async def run(self):
        if not await self.connect():
            return
        print(f"{DIM}Commands: /users /s [user] [msg] /anchor [user] /unanchor /help /exit{RESET}")
        receiver = asyncio.create_task(self.receiver())
        typer = asyncio.create_task(self.input_loop())
        done, pending = await asyncio.wait({receiver, typer}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        try:
            self.writer.close()
        except Exception:
            pass


async def amain():
    ap = argparse.ArgumentParser(description="Kiffy v2 terminal client")
    ap.add_argument("host", nargs="?", help="server IP/hostname")
    ap.add_argument("-p", "--port", type=int, default=8888)
    ap.add_argument("-u", "--user", help="username")
    ap.add_argument("--psk", help="server passphrase (enables encryption)")
    args = ap.parse_args()

    print(f"{GREEN}⚡ KIFFY{RESET} — freedom to communicate")
    host = args.host or input("📍 Server address: ").strip()
    name = args.user or input("👤 Username: ").strip()
    psk = args.psk or getpass.getpass("🔑 Passphrase (empty if server has none): ").strip() or None

    client = KiffyClient(host, args.port, psk)
    client.name = name
    await client.run()


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        print()
