#!/usr/bin/env bash
# run_loadtest.sh <binary> [loadtest.py args...]
# Boots a LOCAL_TEST server with a raised FD limit, then runs the load generator.
# Example: run_loadtest.sh /tmp/sl_new --conns 20000 --procs 16 --group 10 --rate 5 --duration 15
BIN="${1:-/tmp/sl_new}"; shift || true
SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SP/.." && pwd)"
RUN="${RUN_DIR:-$HOME/sl-run}"

ulimit -n 1048576 2>/dev/null || ulimit -n 200000 2>/dev/null || true
echo "server+client fd limit: $(ulimit -n)"

mkdir -p "$RUN/messages_db"; ln -sfn "$REPO/ssl" "$RUN/ssl"
rm -f "$RUN/messages_db/"*.mdb 2>/dev/null
cd "$RUN" || exit 1

"$BIN" > /tmp/srv_load.log 2>&1 &
SRVPID=$!
ok=0
for i in $(seq 1 150); do
  if (exec 3<>/dev/tcp/127.0.0.1/9001) 2>/dev/null; then exec 3>&- 3<&-; ok=1; break; fi
  if ! kill -0 $SRVPID 2>/dev/null; then echo "SERVER DIED"; tail -20 /tmp/srv_load.log; exit 1; fi
  sleep 0.2
done
[ "$ok" = 1 ] || { echo "no listen"; kill -9 $SRVPID 2>/dev/null; exit 1; }
sleep 0.5

python3 "$SP/loadtest.py" --host 127.0.0.1 --port 9001 "$@"
RC=$?

kill -9 $SRVPID 2>/dev/null; wait $SRVPID 2>/dev/null
echo "--- server log tail ---"; tail -3 /tmp/srv_load.log
exit $RC
