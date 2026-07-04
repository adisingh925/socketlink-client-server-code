#!/usr/bin/env bash
# run_webhook_demo.sh <binary> <label>
# Boots the mock webhook (1s handshake stall) + a LOCAL_TEST server with
# SL_TEST_WEBHOOK=1, then measures message-delivery latency while webhooks fire.
BIN="$1"; LABEL="$2"
SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # this tests/ dir
REPO="$(cd "$SP/.." && pwd)"                          # repo root (has ./ssl)
RUN="${RUN_DIR:-$HOME/sl-run}"

mkdir -p "$RUN/messages_db"; ln -sfn "$REPO/ssl" "$RUN/ssl"
rm -f "$RUN/messages_db/"*.mdb 2>/dev/null

# generate a throwaway self-signed cert for the mock if missing
if [ ! -f /tmp/mock_cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -keyout /tmp/mock_key.pem -out /tmp/mock_cert.pem \
    -days 2 -nodes -subj "/CN=localhost" 2>/dev/null
fi

# start mock webhook (1s handshake stall)
python3 "$SP/mock_webhook.py" 1.0 > "/tmp/mock_$LABEL.log" 2>&1 &
MOCKPID=$!
for i in $(seq 1 50); do grep -q "mock webhook on" "/tmp/mock_$LABEL.log" 2>/dev/null && break; sleep 0.1; done

cd "$RUN"
SL_TEST_WEBHOOK=1 "$BIN" > "/tmp/srv_$LABEL.log" 2>&1 &
SRVPID=$!
ok=0
for i in $(seq 1 100); do
  if (exec 3<>/dev/tcp/127.0.0.1/9001) 2>/dev/null; then exec 3>&- 3<&-; ok=1; break; fi
  if ! kill -0 $SRVPID 2>/dev/null; then echo "SERVER DIED ($LABEL)"; tail -20 "/tmp/srv_$LABEL.log"; kill -9 $MOCKPID 2>/dev/null; exit 1; fi
  sleep 0.2
done
[ "$ok" = 1 ] || { echo "no listen"; kill -9 $SRVPID $MOCKPID 2>/dev/null; exit 1; }
sleep 0.5

python3 "$SP/webhook_demo.py" 127.0.0.1 9001 "$LABEL"
RC=$?

sleep 1.5   # let background webhook dispatch drain a bit (new build)
echo "--- mock $LABEL final: $(grep webhook_requests /tmp/mock_$LABEL.log | tail -1)"

kill -9 $SRVPID 2>/dev/null; wait $SRVPID 2>/dev/null
kill -9 $MOCKPID 2>/dev/null; wait $MOCKPID 2>/dev/null
exit $RC
