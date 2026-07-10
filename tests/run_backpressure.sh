#!/usr/bin/env bash
# run_backpressure.sh <binary>
# Boots the server, floods it via non-reading subscribers, and reports whether it
# survived (alive), stayed memory-bounded (peak RSS), kept a healthy client
# responsive, and how many messages it dropped. Regression guard for the
# .dropped-handler stack-overflow crash.
BIN="${1:-$HOME/sl-bin/sl_new}"
SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SP/.." && pwd)"
RUN="${RUN_DIR:-$HOME/sl-run}"

mkdir -p "$RUN/messages_db"; ln -sfn "$REPO/ssl" "$RUN/ssl"; rm -f "$RUN/messages_db/"*.mdb 2>/dev/null
pkill -9 -f "$BIN" 2>/dev/null; sleep 1
cd "$RUN"; "$BIN" > /tmp/bp_srv.log 2>&1 &

SPID=""
for i in $(seq 1 100); do
  SPID=$(pgrep -f "$BIN" | head -1)
  [ -n "$SPID" ] && (exec 3<>/dev/tcp/127.0.0.1/9001) 2>/dev/null && { exec 3>&- 3<&-; break; }
  sleep 0.2
done
[ -z "$SPID" ] && { echo "server failed to start"; exit 1; }

( m=0; for i in $(seq 1 60); do r=$(awk "/VmRSS/{print \$2}" /proc/$SPID/status 2>/dev/null); [ -n "$r" ] && [ "$r" -gt "$m" ] && m=$r; echo $m > /tmp/bp_rss; sleep 0.5; done ) & SAMP=$!

N_SLOW="${N_SLOW:-150}" DURATION="${DURATION:-10}" python3 "$SP/backpressure_test.py"
kill $SAMP 2>/dev/null

echo "--- alive check ---"
kill -0 $SPID 2>/dev/null && echo "server: ALIVE (survived backpressure flood)" || echo "server: CRASHED"
echo "peak RSS: $(( $(cat /tmp/bp_rss 2>/dev/null || echo 0) / 1024 )) MB"
python3 -c "
import http.client,ssl,json
c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);c.check_hostname=0;c.verify_mode=ssl.CERT_NONE
h=http.client.HTTPSConnection('127.0.0.1',9001,context=c,timeout=5)
h.request('GET','/api/v1/metrics',headers={'api-key':'test-admin-key'})
print('dropped_messages:', json.loads(h.getresponse().read())['dropped_messages'])
" 2>/dev/null || echo "metrics unreachable"

pkill -9 -f "$BIN" 2>/dev/null
