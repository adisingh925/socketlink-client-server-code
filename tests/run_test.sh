#!/usr/bin/env bash
# run_test.sh <binary> <label>
# Boots a LOCAL_TEST server binary, waits for it to listen, runs wsclient.py, tears down.
BIN="$1"; LABEL="$2"
SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # this tests/ dir
REPO="$(cd "$SP/.." && pwd)"                          # repo root (has ./ssl)
# Run dir must be on a native Linux fs (LMDB MDB_WRITEMAP); override with RUN_DIR=.
RUN="${RUN_DIR:-$HOME/sl-run}"

mkdir -p "$RUN/messages_db"
ln -sfn "$REPO/ssl" "$RUN/ssl"
rm -f "$RUN/messages_db/"*.mdb 2>/dev/null
cd "$RUN" || exit 1

"$BIN" > "/tmp/srv_$LABEL.log" 2>&1 &
SRVPID=$!

# wait until it accepts TCP on 8080 (max ~20s)
ok=0
for i in $(seq 1 100); do
  if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then exec 3>&- 3<&-; ok=1; break; fi
  if ! kill -0 $SRVPID 2>/dev/null; then echo "SERVER DIED EARLY ($LABEL)"; tail -20 "/tmp/srv_$LABEL.log"; exit 1; fi
  sleep 0.2
done
if [ "$ok" != "1" ]; then echo "SERVER NEVER LISTENED ($LABEL)"; tail -20 "/tmp/srv_$LABEL.log"; kill $SRVPID 2>/dev/null; exit 1; fi
sleep 0.5

python3 "$SP/wsclient.py" 127.0.0.1 8080 "$LABEL"
RC=$?

kill -9 $SRVPID 2>/dev/null; wait $SRVPID 2>/dev/null
exit $RC
