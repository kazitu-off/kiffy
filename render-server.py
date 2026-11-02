#!/usr/bin/env python3
"""
Render.com / cloud entry point.

Cloud platforms set $PORT and cannot run interactive prompts, so this wrapper
starts the same Kiffy v2 server headless:

    admin password: $KIFFY_ADMIN_PASSWORD  (random, printed once, if unset)
    PSK passphrase: $KIFFY_PSK             (optional, needs `cryptography`)

Run:  python render-server.py
"""

import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kiffy_server import KiffyServer, main  # noqa: F401


def run():
    port = int(os.environ.get("PORT", os.environ.get("KIFFY_PORT", 8888)))
    password = os.environ.get("KIFFY_ADMIN_PASSWORD")
    if not password:
        password = secrets.token_urlsafe(12)
        print(f"Generated admin password (username 'admin'): {password}", flush=True)

    srv = KiffyServer("0.0.0.0", port, psk=os.environ.get("KIFFY_PSK"), admin_password=password)
    if srv.psk:
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            print("warning: KIFFY_PSK set but `cryptography` is missing — running plain", flush=True)
            srv.psk = None
        else:
            import base64
            import hashlib
            raw = hashlib.sha256((srv.psk + "|" + srv.nonce).encode()).digest()
            srv.cipher = Fernet(base64.urlsafe_b64encode(raw))

    import asyncio
    try:
        asyncio.run(srv.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
