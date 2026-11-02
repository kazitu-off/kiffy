#!/usr/bin/env python3
"""
Benchmark for the Kiffy v2 server (stdlib only).

Measures, against a freshly spawned server on a scratch port:
  1. round-trip latency  — ping/pong, 200 sequential probes
  2. broadcast fan-out   — one client sends, N clients listen (300 msgs, 100/200 clients)
  3. chat throughput     — C clients each sending M messages (pipelined TCP)
  4. idle concurrency    — how many concurrent connections the event loop holds

Usage:  python3 benchmark.py [path-to-kiffy_server.py]
"""

import asyncio
import json
import os
import signal
import statistics
import subprocess
import sys
import time

PORT = int(os.environ.get("KIFFY_BENCH_PORT", 8901))
SERVER = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "kiffy_server.py")


class Client:
    def __init__(self, reader, writer, name):
        self.reader, self.writer, self.name = reader, writer, name

    async def send(self, obj):
        p = json.dumps(obj, ensure_ascii=False).encode()
        self.writer.write(len(p).to_bytes(4, "big") + p)
        await self.writer.drain()

    async def recv(self, timeout=10):
        h = await asyncio.wait_for(self.reader.readexactly(4), timeout)
        p = await asyncio.wait_for(self.reader.readexactly(int.from_bytes(h, "big")), timeout)
        return json.loads(p)

    async def until(self, t_type, timeout=10):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            m = await self.recv(max(0.05, end - time.monotonic()))
            if m is None:
                return None
            if m.get("t") == t_type:
                return m
        return None


async def connect(name):
    r, w = await asyncio.open_connection("127.0.0.1", PORT)
    c = Client(r, w, name)
    await c.send({"t": "hello", "v": 2, "user": name})
    w = await c.until("welcome")
    assert w, f"{name}: no welcome"
    return c


async def bench_latency():
    c = await connect("bench_ping")
    rtt = []
    for _ in range(200):
        t0 = time.perf_counter()
        await c.send({"t": "ping", "ts": 1})
        m = await c.until("pong")
        assert m
        rtt.append((time.perf_counter() - t0) * 1000)
    await c.send({"t": "exit"})
    return rtt


async def bench_fanout(n_listeners):
    listeners = []
    for i in range(n_listeners):
        listeners.append(await connect(f"fan{i}"))
    talker = await connect("fan_talker")

    t0 = time.perf_counter()
    total = 300
    for i in range(total):
        await talker.send({"t": "msg", "text": f"m{i}"})

    async def count_received(c):
        seen = 0
        end = time.monotonic() + 30
        while seen < total and time.monotonic() < end:
            m = await c.recv(30)
            if m is None:
                break
            if m.get("t") == "msg" and m.get("from") == "fan_talker":
                seen += 1
        return seen

    got = await asyncio.gather(*(count_received(c) for c in listeners))
    dt = time.perf_counter() - t0
    delivered = sum(got)
    for c in listeners + [talker]:
        c.writer.close()

    msgs_per_sec = delivered / dt
    fanout_per_sec = delivered * n_listeners / dt
    ok = all(g == total for g in got)
    return dt, delivered, msgs_per_sec, fanout_per_sec, ok


async def bench_throughput(n_clients, per_client):
    clients = []
    for i in range(n_clients):
        clients.append(await connect(f"thr{i}"))

    sent = [0] * n_clients

    async def blast(idx, c):
        for j in range(per_client):
            await c.send({"t": "msg", "text": "x" * 100})
            sent[idx] += 1

    t0 = time.perf_counter()
    await asyncio.gather(*(blast(i, c) for i, c in enumerate(clients)))
    send_done = time.perf_counter() - t0

    # count deliveries: every client receives every message except its own
    expected = [n_clients * per_client - per_client] * n_clients

    async def drain(idx, c):
        seen = 0
        while seen < expected[idx]:
            m = await c.recv(30)
            if m is None:
                break
            if m.get("t") == "msg" and m.get("from", "").startswith("thr"):
                seen += 1
        return seen

    t1 = time.perf_counter()
    got = await asyncio.gather(*(drain(i, c) for i, c in enumerate(clients)))
    dt = time.perf_counter() - t1
    for c in clients:
        c.writer.close()
    total_msgs = n_clients * per_client
    return total_msgs, sent, got, dt, total_msgs / dt


async def bench_concurrency(target):
    socks = []
    try:
        t0 = time.perf_counter()
        for i in range(target):
            r, w = await asyncio.open_connection("127.0.0.1", PORT)
            p = json.dumps({"t": "hello", "v": 2, "user": f"idle{i}"}).encode()
            w.write(len(p).to_bytes(4, "big") + p)
            socks.append((r, w))
        # drain welcome of a sample to confirm liveness
        r, w = socks[-1]
        h = await asyncio.wait_for(r.readexactly(4), 10)
        await asyncio.wait_for(r.readexactly(int.from_bytes(h, "big")), 10)
        dt = time.perf_counter() - t0
        return len(socks), dt
    finally:
        for r, w in socks:
            try:
                w.close()
            except Exception:
                pass


async def main():
    env = dict(os.environ, KIFFY_PORT=str(PORT), KIFFY_ADMIN_PASSWORD="bench",
               KIFFY_RATE_CAP="100000", KIFFY_RATE_PER_SEC="100000")
    proc = subprocess.Popen([sys.executable, SERVER], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        await asyncio.sleep(0.8)

        print("Kiffy v2 benchmark\n" + "=" * 56)

        rtt = await bench_latency()
        print(f"ping-pong latency   : p50 {statistics.median(rtt):.2f} ms   "
              f"p95 {sorted(rtt)[int(len(rtt)*0.95)]:.2f} ms   "
              f"max {max(rtt):.2f} ms   (200 probes)")

        for n in (100, 200):
            dt, delivered, mps, fps, ok = await bench_fanout(n)
            status = "ok" if ok else "INCOMPLETE"
            print(f"broadcast {n:3d} peers  : {delivered} msgs in {dt:.2f}s  "
                  f"= {mps:8.0f} msg/s  ({fps:9.0f} deliveries/s)  [{status}]")

        total, sent, got, dt, tps = await bench_throughput(50, 200)
        ok = all(g == 50 * 200 - 200 for g in got)
        deliveries = sum(got)
        print(f"throughput 50x200   : {total} msgs sent, {deliveries} deliveries complete: {ok}, "
              f"{dt:.2f}s  = {deliveries/dt:8.0f} deliveries/s sustained")

        target = 2000 if "--full" in sys.argv else 500
        n, dt = await bench_concurrency(target)
        print(f"concurrent sessions : {n} live connections in {dt:.2f}s")

        print("=" * 56)
        print(f"server: {SERVER} (single asyncio event loop, one CPU)")
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    asyncio.run(main())
