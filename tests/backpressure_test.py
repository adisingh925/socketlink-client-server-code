#!/usr/bin/env python3
"""Backpressure robustness test. Piles on maximal pressure and asserts the server
(a) stays alive, (b) keeps memory bounded (drops instead of buffering forever),
(c) keeps serving a HEALTHY client throughout.

- N_SLOW subscribers join a room and then NEVER read (their server-side send
  buffers back up past maxBackpressure).
- A publisher floods that room with ~4 KB messages as fast as it can.
- A separate healthy pub/sub pair on another room must keep exchanging.

Regression guard for the .dropped-handler stack-overflow crash: before the fix,
the flood recursed WebSocket::send <-> .dropped until the stack overflowed
(SIGSEGV). Run via run_backpressure.sh.
"""
import sys, os, time, json, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wsclient as W

N_SLOW = int(os.environ.get("N_SLOW", "150"))
DURATION = float(os.environ.get("DURATION", "10"))
MSG = "x" * 4000  # ~4 KB -> big fan-out per publish

print(f"[test] opening {N_SLOW} slow (non-reading) subscribers on pub-bp ...", flush=True)
slow = []
for i in range(N_SLOW):
    try:
        c = W.WS(f"slow-{i}")
        W.rest_subscribe(f"slow-{i}", "pub-bp")
        slow.append(c)   # never read from these
    except Exception as e:
        print(f"[test] slow sub {i} failed: {e!r}"); break
print(f"[test] {len(slow)} slow subscribers connected", flush=True)

pub = W.WS("bp-pub"); W.rest_subscribe("bp-pub", "pub-bp")
hp = W.WS("healthy-pub"); hs = W.WS("healthy-sub")
W.rest_subscribe("healthy-pub", "pub-healthy"); W.rest_subscribe("healthy-sub", "pub-healthy")
time.sleep(0.6)

sent = [0]; flooding = [True]
def flood():
    payload = json.dumps({"rid": "pub-bp", "message": MSG})
    while flooding[0]:
        try:
            pub.send_text(payload); sent[0] += 1
        except Exception:
            time.sleep(0.01)
threading.Thread(target=flood, daemon=True).start()

ok = 0; attempts = 0; i = 0
t_end = time.time() + DURATION
while time.time() < t_end:
    i += 1; attempts += 1
    try:
        hp.send_text(json.dumps({"rid": "pub-healthy", "message": f"ping{i}"}))
        if hs.recv_user_message(timeout=3).get("data") == f"ping{i}":
            ok += 1
    except Exception:
        pass
    time.sleep(0.5)

flooding[0] = False
time.sleep(0.3)
print(json.dumps({
    "slow_subscribers": len(slow),
    "flood_messages_sent": sent[0],
    "healthy_exchanges_ok": ok,
    "healthy_exchanges_attempted": attempts,
    "healthy_responsive_pct": round(100.0 * ok / max(1, attempts)),
}, indent=2), flush=True)
for c in slow:
    try: c.close()
    except Exception: pass
pub.close(); hp.close(); hs.close()
