#!/usr/bin/env python3
"""
Kiffy Mobile Host v2.2.0 — Standalone mobile server runner.
Standard library only, 0 dependencies. Optimized for Android (Termux / Pydroid 3 / QPython) and PC.

Listens on 0.0.0.0:8888 and serves:
  - WebSocket (ws://<ip>:8888/ws) for mobile & web apps
  - HTTP web chat (http://<ip>:8888/app.html) with Material You MD3
  - Framed TCP for terminal clients
"""

import os
import sys

# Ensure UTF-8 output on all platforms
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Import the core KiffyServer from kiffy_server.py
base_dir = os.path.dirname(os.path.abspath(__file__))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from kiffy_server import KiffyServer, main as server_main

if __name__ == "__main__":
    print("\n" + "=" * 54)
    print("  ⚡ KIFFY MOBILE HOST v2.2.0 — Material You (MD3)")
    print("=" * 54)
    print("  ✓ Full host support enabled")
    print("  ✓ Ready for Web, WebSocket, and Regular TCP clients")
    print("  ✓ Weight < 1 MB (well under 50 MB)")
    print("=" * 54 + "\n")
    server_main()
