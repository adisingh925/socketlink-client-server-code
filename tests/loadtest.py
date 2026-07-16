#!/usr/bin/env python3
"""Multi-process asyncio load generator for SocketlinkClientServer (LOCAL_TEST).

Opens a large number of WebSocket(TLS) connections spread across worker
processes, subscribes each into a small fan-out room, then has every connection
send at a fixed rate for a fixed window. Reports client-side send/receive
throughput and cross-checks the server's own /api/v1/metrics (authoritative,
since the Python client's receive side is the usual bottleneck).

Scale past the ~28k ephemeral-port limit by binding client sockets across
several loopback source IPs (127.0.0.1, 127.0.0.2, ... — all of 127/8 is lo).

Usage:
  loadtest.py --conns 20000 --procs 16 --group 10 --rate 5 --duration 15
"""
import argparse, asyncio, base64, json, os, queue, ssl, struct, sys, time
import multiprocessing as mp
import resource
import http.client

CLIENT_KEY = "change-me-client-key"
ADMIN_KEY  = "change-me-admin-key"
PAYLOAD = b'{"rid":"%s","message":"x"}'  # filled per room

def raise_fds():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    except Exception:
        pass

def make_ctx():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

def build_text_frame(payload: bytes) -> bytes:
    n = len(payload)
    mask = os.urandom(4)
    hdr = bytearray([0x81])
    if n < 126:
        hdr.append(0x80 | n)
    elif n < 65536:
        hdr.append(0x80 | 126); hdr += struct.pack("!H", n)
    else:
        hdr.append(0x80 | 127); hdr += struct.pack("!Q", n)
    hdr += mask
    return bytes(hdr) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

async def read_frame(reader):
    """Read and discard one WS frame; return opcode. Raises on EOF."""
    h = await reader.readexactly(2)
    b1 = h[1]
    ln = b1 & 0x7F
    if ln == 126:
        ln = struct.unpack("!H", await reader.readexactly(2))[0]
    elif ln == 127:
        ln = struct.unpack("!Q", await reader.readexactly(8))[0]
    if b1 & 0x80:
        await reader.readexactly(4)
    if ln:
        await reader.readexactly(ln)
    return h[0] & 0x0F

async def ws_connect(host, port, src_ip, uid, ctx):
    reader, writer = await asyncio.open_connection(
        host, port, ssl=ctx,
        server_hostname=("localtest.socketlink.io" if ctx else None),  # SNI only meaningful with TLS
        local_addr=((src_ip, 0) if src_ip else None),  # empty src_ip => let the OS pick (remote targets)
    )
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           f"Sec-WebSocket-Version: 13\r\napi-key: {CLIENT_KEY}\r\nuid: {uid}\r\n\r\n")
    writer.write(req.encode()); await writer.drain()
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
    if b"101" not in head.split(b"\r\n", 1)[0]:
        raise RuntimeError("upgrade failed: " + head.split(b"\r\n",1)[0].decode("latin1"))
    return reader, writer

async def subscribe(pool, host, rid, uid):
    reader, writer = await pool.get()
    try:
        req = (f"GET /api/v1/users/subscribe/room/{rid} HTTP/1.1\r\nHost: {host}\r\n"
               f"api-key: {CLIENT_KEY}\r\nuid: {uid}\r\nConnection: keep-alive\r\n\r\n")
        writer.write(req.encode()); await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
        cl = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                cl = int(line.split(b":", 1)[1])
        if cl:
            await reader.readexactly(cl)
        return b" 200 " in head or head.split(b"\r\n",1)[0].endswith(b"200 OK")
    finally:
        pool.put_nowait((reader, writer))

def worker(cfg, shard_start, shard_end, ready_q, result_q, go_time):
    raise_fds()
    try:
        asyncio.run(worker_async(cfg, shard_start, shard_end, ready_q, result_q, go_time))
    except Exception as e:
        try: result_q.put({"error": repr(e), "sent": 0, "recv": 0, "connected": 0})
        except Exception: pass

async def worker_async(cfg, shard_start, shard_end, ready_q, result_q, go_time):
    host, port = cfg["host"], cfg["port"]
    src_ips = cfg["src_ips"]
    group = cfg["group"]
    connected = 0
    sent = [0]; recv = [0]
    ready_sent = False
    err = None
    try:
        ctx = make_ctx() if cfg["tls"] else None

        # subscribe pool (keep-alive HTTP(S) connections)
        pool = asyncio.Queue()
        for k in range(cfg["pool"]):
            _s = src_ips[k % len(src_ips)]
            r, w = await asyncio.open_connection(
                host, port, ssl=ctx,
                server_hostname=("localtest.socketlink.io" if ctx else None),
                local_addr=((_s, 0) if _s else None))
            pool.put_nowait((r, w))

        conns = []          # (reader, writer, frame)
        reader_tasks = []   # started at connect so pings are answered during long ramps
        counting = [False]  # count received data frames only inside the measurement window
        sem = asyncio.Semaphore(cfg["concurrency"])

        async def reader_task(r, w):
            # Runs from the moment the connection is established: replies PONG to
            # server PINGs (otherwise long setup ramps make early connections look
            # idle and the server closes them), counts data frames once counting is on.
            while True:
                try:
                    op = await read_frame(r)
                    if op == 0x9:                      # PING -> masked empty PONG
                        w.write(b"\x8a\x80" + os.urandom(4))
                        await w.drain()
                    elif counting[0] and op in (0x1, 0x2):
                        recv[0] += 1
                except Exception:
                    return

        async def setup(i):
            nonlocal connected
            uid = f"u{i}"
            rid = f"pub-grp-{i // group}"
            src = src_ips[i % len(src_ips)]
            async with sem:
                try:
                    r, w = await ws_connect(host, port, src, uid, ctx)
                    ok = await subscribe(pool, host, rid, uid)
                    if not ok:
                        w.close(); return
                    frame = build_text_frame(PAYLOAD % rid.encode())
                    conns.append((r, w, frame))
                    reader_tasks.append(asyncio.create_task(reader_task(r, w)))
                    connected += 1
                except Exception:
                    return

        await asyncio.gather(*[setup(i) for i in range(shard_start, shard_end)])
        ready_q.put(connected); ready_sent = True

        # wait until the coordinated start time
        now = time.time()
        if go_time.value > now:
            await asyncio.sleep(go_time.value - now)

        stop = time.time() + cfg["duration"]
        interval = (1.0 / cfg["rate"]) if cfg["rate"] > 0 else 0
        counting[0] = True

        async def sender(w, frame):
            while time.time() < stop:
                try:
                    w.write(frame); await w.drain(); sent[0] += 1
                except Exception:
                    return
                if interval:
                    await asyncio.sleep(interval)
                else:
                    await asyncio.sleep(0)

        tasks = [asyncio.create_task(sender(w, frame)) for (r, w, frame) in conns]
        await asyncio.sleep(cfg["duration"] + 0.2)
        for t in tasks + reader_tasks:
            t.cancel()
        await asyncio.gather(*tasks, *reader_tasks, return_exceptions=True)
    except Exception as e:
        err = repr(e)
    finally:
        # guarantee exactly one ready + one result so the launcher never blocks
        if not ready_sent:
            try: ready_q.put(connected)
            except Exception: pass
        try:
            result_q.put({"connected": connected, "sent": sent[0], "recv": recv[0], "error": err})
        except Exception:
            pass

def get_metrics(host, port, tls=True):
    if tls:
        conn = http.client.HTTPSConnection(host, port, context=make_ctx(), timeout=15)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=15)
    try:
        conn.request("GET", "/api/v1/metrics", headers={"api-key": ADMIN_KEY})
        r = conn.getresponse()
        return json.loads(r.read().decode())
    finally:
        conn.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9001)
    ap.add_argument("--conns", type=int, default=20000)
    ap.add_argument("--procs", type=int, default=16)
    ap.add_argument("--group", type=int, default=10, help="room size (fan-out group)")
    ap.add_argument("--rate", type=float, default=5.0, help="msgs/sec per connection (0=max)")
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--pool", type=int, default=16, help="subscribe conns per worker")
    ap.add_argument("--concurrency", type=int, default=400, help="concurrent handshakes per worker")
    ap.add_argument("--src-ips", default="127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5,127.0.0.6,127.0.0.7,127.0.0.8")
    ap.add_argument("--no-tls", action="store_true", help="plaintext ws:// (TLS terminated upstream)")
    args = ap.parse_args()

    tls = not args.no_tls
    src_ips = args.src_ips.split(",")
    cfg = dict(host=args.host, port=args.port, group=args.group, rate=args.rate,
               duration=args.duration, pool=args.pool, concurrency=args.concurrency,
               src_ips=src_ips, tls=tls)

    per = args.conns // args.procs
    shards = [(i * per, (i + 1) * per if i < args.procs - 1 else args.conns) for i in range(args.procs)]

    ready_q = mp.Queue(); result_q = mp.Queue()
    go_time = mp.Value("d", 0.0)

    procs = []
    for (s, e) in shards:
        p = mp.Process(target=worker, args=(cfg, s, e, ready_q, result_q, go_time))
        p.start(); procs.append(p)

    # wait for all workers to finish connecting
    print(f"[launcher] connecting {args.conns} conns across {args.procs} procs "
          f"(group={args.group}, rate={args.rate}/s, dur={args.duration}s)...", flush=True)
    total_connected = 0
    got = 0
    t_setup = time.time()
    while got < args.procs:
        try:
            total_connected += ready_q.get(timeout=180)
            got += 1
        except queue.Empty:
            alive = sum(1 for p in procs if p.is_alive())
            print(f"[launcher] WARNING: ready timeout ({got}/{args.procs} reported, {alive} alive) "
                  f"- likely OOM/FD limit; proceeding", flush=True)
            break
    setup_s = time.time() - t_setup
    print(f"[launcher] connected {total_connected}/{args.conns} in {setup_s:.1f}s "
          f"({got}/{args.procs} workers ready)", flush=True)

    # coordinated start ~1s from now
    m0 = get_metrics(args.host, args.port, tls)      # all connections are up at this point
    conns_at_start = m0["connections"]
    go_time.value = time.time() + 1.0
    time.sleep(1.0 + args.duration - 0.3)
    m1 = get_metrics(args.host, args.port, tls)      # read just before workers tear down
    conns_at_end = m1["connections"]
    window = args.duration

    total_sent = total_recv = 0
    errors = []
    got = 0
    while got < args.procs:
        try:
            r = result_q.get(timeout=60); got += 1
        except queue.Empty:
            break
        total_sent += r.get("sent", 0); total_recv += r.get("recv", 0)
        if r.get("error"):
            errors.append(r["error"])
    for p in procs:
        p.join(timeout=10)
        if p.is_alive():
            p.terminate()

    d_msgs = m1["messages_sent"] - m0["messages_sent"]
    d_pay  = m1["total_payload_sent"] - m0["total_payload_sent"]
    d_drop = m1["dropped_messages"] - m0["dropped_messages"]

    print(json.dumps({
        "target_conns": args.conns,
        "connected": total_connected,
        "setup_s": round(setup_s, 1),
        "group_size": args.group,
        "rate_per_conn": args.rate,
        "window_s": window,
        "client": {
            "sent": total_sent,
            "recv": total_recv,
            "send_rate_msgs_s": round(total_sent / window),
            "recv_rate_msgs_s": round(total_recv / window),
        },
        "connections_reported_start": conns_at_start,
        "connections_reported_end": conns_at_end,
        "server_metrics_delta": {
            # NOTE: server messages_sent counts only *local* (same-worker) subscribers
            # per publish (numSubscribers is per-app), so it undercounts cross-thread
            # fan-out. client.recv is the truer delivery count.
            "messages_sent_local_only": d_msgs,
            "payload_bytes": d_pay,
            "payload_MB_s": round(d_pay / window / 1e6, 2),
            "dropped_messages": d_drop,
            "avg_latency": m1["average_latency"],
        },
        "worker_errors_sample": errors[:5],
    }, indent=2), flush=True)

if __name__ == "__main__":
    main()
