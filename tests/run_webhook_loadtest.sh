#!/usr/bin/env bash
# run_webhook_loadtest.sh [binary] — webhook path load test, all local:
#   - fire-and-forget webhooks (ON_MESSAGE per message + lifecycle events)
#     through the dispatcher thread under a 2k-conn message load
#   - private-room verification through the bounded pool (ON_VERIFICATION_REQUEST)
#   - keep-alive DRAIN correctness: the mock answers every request with a body on
#     a reused connection, so any response-framing desync shows up as failed
#     verifications / garbage statuses
#   - deny path: mock killed -> private subscribe must 403
# Uses tests/mock_webhook.py (TLS on 127.0.0.1:8443, keep-alive, counts requests).
set -u
SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SP/.." && pwd)"
RUN="${RUN_DIR:-$HOME/sl-run}"
BIN="${1:-$REPO/build/socketlink}"
ADMIN='api-key: change-me-admin-key'

ulimit -n 1048576 2>/dev/null || true
mkdir -p "$RUN/messages_db"
rm -f "$RUN/messages_db/"*.mdb 2>/dev/null

# throwaway self-signed cert for the mock
if [ ! -f /tmp/mock_cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -keyout /tmp/mock_key.pem -out /tmp/mock_cert.pem \
    -days 2 -nodes -subj "/CN=localhost" 2>/dev/null
fi

python3 "$SP/mock_webhook.py" 0 > /tmp/mock_wh.log 2>&1 &
MOCKPID=$!
for i in $(seq 1 50); do grep -q "mock webhook on" /tmp/mock_wh.log 2>/dev/null && break; sleep 0.1; done

cd "$RUN" || exit 1
"$BIN" > /tmp/srv_wh.log 2>&1 &
SRVPID=$!
for i in $(seq 1 100); do
  if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then exec 3>&- 3<&-; break; fi
  kill -0 $SRVPID 2>/dev/null || { echo "SERVER DIED"; tail -20 /tmp/srv_wh.log; kill -9 $MOCKPID; exit 1; }
  sleep 0.2
done
sleep 0.5

echo "=========== configuring webhooks (all events, HMAC secret, port 8443) ==========="
curl -s -X POST -H "$ADMIN" \
  -d '{"webhook_base_url":"localhost","webhook_path":"/hook","webhook_port":8443,"webhook_secret":"whsecret","webhooks":126}' \
  localhost:8080/api/v1/invalidate; echo
sleep 1

echo "=========== verification via bounded pool: 20 private-room subscribes ==========="
cd "$SP"
python3 - <<'PYEOF'
import wsclient, http.client, time
ok = fail = 0
conns = []
for n in range(20):
    uid = f"ver-{n}"
    conns.append(wsclient.WS(uid))
    c = http.client.HTTPConnection("127.0.0.1", 8080, timeout=15)
    c.request("GET", f"/api/v1/users/subscribe/room/pri-ver-{n}",
              headers={"api-key": "change-me-client-key", "uid": uid})
    r = c.getresponse(); r.read(); c.close()
    ok += (r.status == 200); fail += (r.status != 200)
print(f"verification approvals: {ok}/20 ok, {fail} failed")
for w in conns: w.close()
PYEOF

echo
echo "=========== fire-and-forget load: 2000 conns, ON_MESSAGE per message ==========="
python3 "$SP/loadtest.py" --host 127.0.0.1 --port 8080 --no-tls \
  --conns 2000 --procs 8 --group 10 --rate 2 --duration 15 --size 256
echo
echo "-- draining dispatcher queue (10s)..."
sleep 10
echo "-- mock request count:   $(grep webhook_requests /tmp/mock_wh.log | tail -1)"
echo "-- server webhook metrics:"
curl -s -H "$ADMIN" localhost:8080/api/v1/metrics | python3 -c 'import json,sys; m=json.load(sys.stdin); print({k:m[k] for k in ("total_success_webhook_calls","total_failed_webhook_calls","dropped_webhook_events")})'

echo
echo "=========== deny path: mock killed -> private subscribe must 403 ==========="
kill -9 $MOCKPID 2>/dev/null; wait $MOCKPID 2>/dev/null
sleep 0.5
python3 - <<'PYEOF'
import wsclient, http.client
w = wsclient.WS("deny-user")
c = http.client.HTTPConnection("127.0.0.1", 8080, timeout=30)
c.request("GET", "/api/v1/users/subscribe/room/pri-deny",
          headers={"api-key": "change-me-client-key", "uid": "deny-user"})
r = c.getresponse(); body = r.read().decode()
print(f"deny status: {r.status} (expected 403) {body[:60]}")
w.close()
PYEOF

kill -TERM $SRVPID 2>/dev/null; sleep 2; kill -9 $SRVPID 2>/dev/null
echo "-- server log tail:"; tail -4 /tmp/srv_wh.log
