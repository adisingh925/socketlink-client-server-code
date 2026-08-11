#!/usr/bin/env python3
"""
Endpoint smoke test: every route, with and without a valid key.

Pins the HTTP contract (status codes and auth behaviour) so a refactor of the
handler boilerplate cannot silently change what clients see. Fast enough to run
on every build.

Usage: endpoint_smoke.py [host] [port]
"""
import json
import sys
import http.client

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
ADMIN = "change-me-admin-key"
CLIENT = "change-me-client-key"

failures = []
checks = 0


def call(method, path, key=None, body=None, uid=None, extra=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
    headers = {}
    if key:
        headers["api-key"] = key
    if uid:
        headers["uid"] = uid
    if extra:
        headers.update(extra)
    payload = json.dumps(body) if body is not None else None
    if payload:
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=payload, headers=headers)
        r = conn.getresponse()
        return r.status, r.read().decode()
    finally:
        conn.close()


def expect(label, got, want):
    global checks
    checks += 1
    if isinstance(want, (list, tuple)):
        ok = got in want
        wantstr = " or ".join(str(w) for w in want)
    else:
        ok = got == want
        wantstr = str(want)
    print(f"  {'ok  ' if ok else 'FAIL'} {label}: got {got}, want {wantstr}")
    if not ok:
        failures.append(label)


print(f"endpoint smoke test against {HOST}:{PORT}\n")

print("unauthenticated requests must be rejected (never 200)")
for method, path, body in [
    ("GET", "/api/v1/metrics", None),
    ("POST", "/api/v1/invalidate", {}),
    ("GET", "/api/v1/mysql/sync", None),
    ("GET", "/api/v1/rooms/users/all", None),
    ("GET", "/api/v1/users/orphan", None),
    ("POST", "/api/v1/rooms/users", {"rid": []}),
    ("GET", "/api/v1/users/subscriptions/all", None),
    ("POST", "/api/v1/users/subscriptions", {"uid": []}),
    ("POST", "/api/v1/broadcast", {"message": "x"}),
    ("POST", "/api/v1/rooms/broadcast", {"message": "x", "rid": []}),
    ("POST", "/api/v1/users/broadcast", {"message": "x", "uid": []}),
    ("POST", "/api/v1/rooms/users/ban", []),
    ("POST", "/api/v1/rooms/users/unban", []),
    ("PUT", "/api/v1/server/messaging/enable", None),
    ("POST", "/api/v1/rooms/messaging/enable", []),
    ("GET", "/api/v1/users/banned", None),
    ("GET", "/api/v1/users/messaging/disabled", None),
    ("DELETE", "/api/v1/database", None),
]:
    st, _ = call(method, path, key="wrong-key", body=body)
    expect(f"{method} {path} (bad key)", st, (401, 403))

print("\nauthenticated admin requests")
st, body = call("GET", "/api/v1/metrics", key=ADMIN)
expect("GET /api/v1/metrics", st, 200)
checks += 1
try:
    m = json.loads(body)
    required = ["connections", "messages_sent", "dropped_messages", "connection_limit",
                "memory_working_set_bytes", "admission_paused", "dropped_db_rows"]
    missing = [k for k in required if k not in m]
    print(f"  {'ok  ' if not missing else 'FAIL'} metrics payload has required fields"
          f"{'' if not missing else ' (missing ' + ','.join(missing) + ')'}")
    if missing:
        failures.append("metrics fields")
except json.JSONDecodeError:
    print("  FAIL metrics payload is not JSON")
    failures.append("metrics json")

for label, method, path, body in [
    ("rooms/users/all", "GET", "/api/v1/rooms/users/all", None),
    ("users/orphan", "GET", "/api/v1/users/orphan", None),
    ("users/subscriptions/all", "GET", "/api/v1/users/subscriptions/all", None),
    ("users/banned", "GET", "/api/v1/users/banned", None),
    ("users/messaging/disabled", "GET", "/api/v1/users/messaging/disabled", None),
    ("rooms/users", "POST", "/api/v1/rooms/users", {"rid": ["pub-none"]}),
    ("users/subscriptions", "POST", "/api/v1/users/subscriptions", {"uid": ["nobody"]}),
    ("broadcast", "POST", "/api/v1/broadcast", {"message": "smoke"}),
    ("rooms/broadcast", "POST", "/api/v1/rooms/broadcast", {"message": "smoke", "rid": ["pub-none"]}),
    ("users/broadcast", "POST", "/api/v1/users/broadcast", {"message": "smoke", "uid": ["nobody"]}),
    ("ban", "POST", "/api/v1/rooms/users/ban", [{"rid": "pub-smoke", "uid": ["ghost"]}]),
    ("unban", "POST", "/api/v1/rooms/users/unban", [{"rid": "pub-smoke", "uid": ["ghost"]}]),
    ("rooms/messaging/disable", "POST", "/api/v1/rooms/messaging/disable", [{"rid": "pub-smoke", "uid": ["ghost"]}]),
    ("rooms/messaging/enable", "POST", "/api/v1/rooms/messaging/enable", [{"rid": "pub-smoke", "uid": ["ghost"]}]),
]:
    st, _ = call(method, path, key=ADMIN, body=body)
    expect(label, st, 200)

print("\nserver-wide messaging toggle")
for action, want in [("disable", 200), ("enable", 200), ("bogus", 400)]:
    st, _ = call("PUT", f"/api/v1/server/messaging/{action}", key=ADMIN)
    expect(f"PUT server/messaging/{action}", st, want)

print("\ninvalid input handling")
st, _ = call("POST", "/api/v1/rooms/messaging/bogus", key=ADMIN, body=[])
expect("POST rooms/messaging/bogus (invalid action)", st, 400)
st, _ = call("POST", "/api/v1/broadcast", key=ADMIN, body=None, extra={"Content-Length": "0"})
expect("POST broadcast (empty body)", st, 400)

print("\nclient-key routes")
st, _ = call("GET", "/api/v1/users/subscribe/room/pub-x", key="wrong", uid="nobody")
expect("subscribe (bad client key)", st, 401)
st, _ = call("GET", "/api/v1/users/subscribe/room/pub-x", key=CLIENT, uid="nobody")
expect("subscribe (unknown uid)", st, 404)
st, _ = call("GET", "/api/v1/users/unsubscribe/room/pub-x", key=CLIENT, uid="nobody")
expect("unsubscribe (unknown uid)", st, 404)
st, _ = call("GET", "/api/v1/messages/room/pub-x", key="wrong", uid="nobody")
expect("messages (bad client key)", st, (401, 403))

print("\nunauthenticated public routes")
st, _ = call("GET", "/api/v1/ping")
expect("GET /api/v1/ping", st, 200)
st, _ = call("GET", "/no/such/route")
expect("GET unknown route", st, 404)

print(f"\n{checks} checks, {len(failures)} failures")
if failures:
    print("failed: " + ", ".join(failures))
sys.exit(1 if failures else 0)
