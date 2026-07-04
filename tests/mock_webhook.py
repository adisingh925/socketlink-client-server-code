#!/usr/bin/env python3
"""Mock HTTPS webhook endpoint that stalls the TLS handshake by DELAY seconds,
simulating a slow customer webhook receiver. Counts requests; prints count."""
import os, socket, ssl, sys, time, threading

HOST, PORT = "127.0.0.1", 8443
DELAY = float(sys.argv[1]) if len(sys.argv) > 1 else 1.0
CERT = os.environ.get("MOCK_CERT", "/tmp/mock_cert.pem")
KEY = os.environ.get("MOCK_KEY", "/tmp/mock_key.pem")

count = [0]
lock = threading.Lock()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)

def handle(conn):
    try:
        time.sleep(DELAY)  # <-- stall the TLS handshake
        s = ctx.wrap_socket(conn, server_side=True)
    except Exception:
        try: conn.close()
        except Exception: pass
        return
    buf = b""
    while True:
        try:
            while b"\r\n\r\n" not in buf:
                d = s.recv(4096)
                if not d: return
                buf += d
            head, buf = buf.split(b"\r\n\r\n", 1)
            cl = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    cl = int(line.split(b":", 1)[1].strip())
            while len(buf) < cl:
                d = s.recv(4096)
                if not d: return
                buf += d
            buf = buf[cl:]
            with lock: count[0] += 1
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
        except Exception:
            return

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, PORT)); srv.listen(50)
print(f"mock webhook on {HOST}:{PORT} handshake_delay={DELAY}s", flush=True)

def accept_loop():
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()
threading.Thread(target=accept_loop, daemon=True).start()

while True:
    time.sleep(0.5)
    print(f"webhook_requests={count[0]}", flush=True)
