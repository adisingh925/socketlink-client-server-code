#!/usr/bin/env python3
"""Pure-stdlib WebSocket client + test driver for the standalone Socketlink server
(plaintext ws:// on 8080; TLS is terminated upstream by a load balancer in prod).
Tests: functional parity (incl. JSON-escaping), latency, throughput (fan-out).
Usage: wsclient.py <host> <port> <label>
"""
import socket, base64, os, struct, json, time, sys, threading, http.client, statistics

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
LABEL = sys.argv[3] if len(sys.argv) > 3 else "server"
CLIENT_KEY = "change-me-client-key"

class WS:
    def __init__(self, uid):
        self.uid = uid
        self.sock = socket.create_connection((HOST, PORT), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"api-key: {CLIENT_KEY}\r\nuid: {uid}\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        resp = self._read_http_head()
        if "101" not in resp.split("\r\n", 1)[0]:
            raise RuntimeError(f"WS upgrade failed for {uid}: {resp.splitlines()[0] if resp else 'no response'}")
        self.buf = b""

    def _read_http_head(self):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.decode("latin1")

    def _recv_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send_text(self, s):
        payload = s.encode()
        header = bytearray([0x81])  # FIN + text
        n = len(payload)
        mask = os.urandom(4)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126); header += struct.pack("!H", n)
        else:
            header.append(0x80 | 127); header += struct.pack("!Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv_frame(self):
        b0, b1 = self._recv_exact(2)
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        if ln == 126:
            ln = struct.unpack("!H", self._recv_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack("!Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else b""
        data = self._recv_exact(ln) if ln else b""
        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        if opcode == 0x9:  # ping -> pong
            self._send_ctrl(0xA, data); return self.recv_frame()
        if opcode == 0x8:  # close
            return ("close", data)
        return (opcode, data)

    def _send_ctrl(self, opcode, data=b""):
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(bytes([0x80 | opcode, 0x80 | len(data)]) + mask + masked)

    def recv_user_message(self, timeout=10):
        """Return the parsed JSON of the next source=user/admin message, skipping system frames."""
        self.sock.settimeout(timeout)
        skipped = []
        while True:
            try:
                op, data = self.recv_frame()
            except (socket.timeout, TimeoutError):
                raise TimeoutError(f"no user message; skipped frames={skipped}")
            if op == "close":
                raise ConnectionError(f"server closed; skipped frames={skipped}")
            if op != 0x1:
                continue
            txt = data.decode()
            try:
                j = json.loads(txt)
            except json.JSONDecodeError:
                return {"__RAW_INVALID_JSON__": txt}
            if j.get("source") in ("user", "admin"):
                return j
            skipped.append(txt[:80])
            # skip server/system frames (latency, joined/left, rate-limit, etc.)

    def close(self):
        try:
            self._send_ctrl(0x8); self.sock.close()
        except Exception:
            pass

def rest_subscribe(uid, rid, retries=15):
    for _ in range(retries):
        conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
        try:
            conn.request("GET", f"/api/v1/users/subscribe/room/{rid}",
                         headers={"api-key": CLIENT_KEY, "uid": uid})
            r = conn.getresponse(); body = r.read().decode()
            if r.status == 200:
                return True
            if r.status == 404:  # connection not registered yet
                time.sleep(0.05); continue
            raise RuntimeError(f"subscribe {rid} for {uid} -> {r.status} {body}")
        finally:
            conn.close()
    raise RuntimeError(f"subscribe {rid} for {uid} kept 404ing")

# ---------------- tests ----------------
results = {"label": LABEL}

def test_functional():
    # This uWS build does not echo a publish back to the publishing socket, so
    # use a separate publisher and subscriber.
    out = {}
    pub = WS("func-pub"); sub = WS("func-sub")
    rest_subscribe("func-pub", "pub-func"); rest_subscribe("func-sub", "pub-func")
    time.sleep(0.4)  # let the deferred ws->subscribe calls take effect
    # plain echo
    pub.send_text(json.dumps({"rid": "pub-func", "message": "hello world"}))
    j = sub.recv_user_message()
    out["echo_ok"] = (j.get("data") == "hello world" and j.get("rid") == "pub-func" and j.get("source") == "user")
    # JSON-escaping: message with quotes/backslash/newline
    tricky = 'he said "hi"\\back\nnewline'
    pub.send_text(json.dumps({"rid": "pub-func", "message": tricky}))
    j2 = sub.recv_user_message()
    out["escaping_valid_json"] = "__RAW_INVALID_JSON__" not in j2
    out["escaping_roundtrip_ok"] = (j2.get("data") == tricky)
    out["escaping_raw"] = j2.get("__RAW_INVALID_JSON__", "")[:120]
    pub.close(); sub.close()
    results["functional"] = out

def test_latency(n=500):
    pub = WS("lat-pub"); sub = WS("lat-sub")
    rest_subscribe("lat-pub", "pub-lat"); rest_subscribe("lat-sub", "pub-lat")
    time.sleep(0.4)
    samples = []
    msg = json.dumps({"rid": "pub-lat", "message": "x"})
    for _ in range(n):
        t0 = time.perf_counter()
        pub.send_text(msg)
        sub.recv_user_message(timeout=10)  # publish -> deliver to a separate subscriber
        samples.append((time.perf_counter() - t0) * 1000.0)
    pub.close(); sub.close()
    samples.sort()
    results["latency_ms"] = {
        "n": n,
        "avg": round(statistics.mean(samples), 3),
        "p50": round(samples[int(n*0.50)], 3),
        "p95": round(samples[int(n*0.95)], 3),
        "p99": round(samples[int(n*0.99)], 3),
        "max": round(samples[-1], 3),
    }

def test_throughput(subs=40, msgs=1500):
    rid = "pub-thr"
    pub = WS("thr-pub")
    rest_subscribe("thr-pub", rid)  # publisher must be subscribed to send to the room
    conns = []
    for i in range(subs):
        uid = f"thr-{i}"
        c = WS(uid)
        rest_subscribe(uid, rid)
        conns.append(c)
    time.sleep(0.6)  # let all deferred subscriptions take effect
    # each of the `subs` subscribers should receive `msgs` user-frames from the publisher
    counts = [0] * subs
    def reader(idx):
        c = conns[idx]
        got = 0
        while got < msgs:
            try:
                c.recv_user_message(timeout=30)
            except Exception:
                break
            got += 1
        counts[idx] = got
    threads = [threading.Thread(target=reader, args=(i,)) for i in range(subs)]
    for t in threads: t.start()
    time.sleep(0.3)  # let readers get scheduled
    payload = json.dumps({"rid": rid, "message": "throughput-benchmark-payload"})
    t0 = time.perf_counter()
    for _ in range(msgs):
        pub.send_text(payload)
    for t in threads: t.join(timeout=60)
    elapsed = time.perf_counter() - t0
    total = sum(counts)
    pub.close()
    for c in conns: c.close()
    results["throughput"] = {
        "subscribers": subs, "msgs_published": msgs,
        "expected_deliveries": subs * msgs,
        "actual_deliveries": total,
        "elapsed_s": round(elapsed, 3),
        "deliveries_per_s": round(total / elapsed) if elapsed > 0 else 0,
    }

if __name__ == "__main__":
    try:
        test_functional()
        test_latency()
        test_throughput()
    except Exception as e:
        results["error"] = repr(e)
    print(json.dumps(results, indent=2))
