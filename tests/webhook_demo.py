#!/usr/bin/env python3
"""Measure message-delivery latency while an ON_MESSAGE webhook fires against a
slow (handshake-stalling) endpoint. Old build blocks the event loop on the
handshake; new build offloads it to the dispatcher thread.
Usage: webhook_demo.py <host> <port> <label>"""
import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # import wsclient from this dir
import wsclient as W

W.HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
W.PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9001
label = sys.argv[3] if len(sys.argv) > 3 else "?"

pub = W.WS("wh-pub"); sub = W.WS("wh-sub")
W.rest_subscribe("wh-pub", "pub-wh"); W.rest_subscribe("wh-sub", "pub-wh")
time.sleep(0.5)

N = 15
sub.sock.settimeout(30)
t0 = time.perf_counter()
for i in range(N):
    pub.send_text(json.dumps({"rid": "pub-wh", "message": f"m{i}"}))
arrivals = []
for i in range(N):
    sub.recv_user_message(timeout=30)
    arrivals.append(round((time.perf_counter() - t0) * 1000, 2))
total = round((time.perf_counter() - t0) * 1000, 2)
pub.close(); sub.close()
print(json.dumps({
    "label": label,
    "messages": N,
    "arrivals_ms": arrivals,
    "max_delivery_ms": max(arrivals),
    "total_ms": total,
}, indent=2))
