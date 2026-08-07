#!/usr/bin/env bash
# run_persistence_loadtest.sh [binary] — load test the PERSISTENCE path locally:
# three identical runs so each layer's cost is separable:
#   1. plain rooms          (no persistence — baseline)
#   2. pub-cache-* rooms    (LMDB write per message, MySQL off)
#   3. pub-cache-* rooms    (LMDB + MySQL batched inserts per message)
#
# Requires a local MySQL reachable at $DB_HOST (default 127.0.0.1:3306,
# root/slpass, database "socketlink"), e.g.:
#   docker run -d --name sl-mysql -e MYSQL_ROOT_PASSWORD=slpass \
#     -e MYSQL_DATABASE=socketlink -p 3306:3306 mysql:8
set -u
SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SP/.." && pwd)"
RUN="${RUN_DIR:-$HOME/sl-run}"
BIN="${1:-$REPO/build/socketlink}"
DB_HOST="${DB_HOST:-127.0.0.1}"
ADMIN='api-key: change-me-admin-key'
LOAD_ARGS="--conns 20000 --procs 16 --group 10 --rate 5 --duration 15 --size 1024"

ulimit -n 1048576 2>/dev/null || true
mkdir -p "$RUN/messages_db"
rm -f "$RUN/messages_db/"*.mdb
cd "$RUN" || exit 1

"$BIN" > /tmp/srv_persist.log 2>&1 &
SRVPID=$!
for i in $(seq 1 100); do
  if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then exec 3>&- 3<&-; break; fi
  kill -0 $SRVPID 2>/dev/null || { echo "SERVER DIED"; tail -20 /tmp/srv_persist.log; exit 1; }
  sleep 0.2
done
sleep 0.5

echo "=========== RUN 1: baseline (plain rooms, no persistence) ==========="
python3 "$SP/loadtest.py" --host 127.0.0.1 --port 8080 --no-tls $LOAD_ARGS
echo

echo "=========== RUN 2: cache rooms -> LMDB writes (MySQL off) ==========="
python3 "$SP/loadtest.py" --host 127.0.0.1 --port 8080 --no-tls $LOAD_ARGS --room-prefix pub-cache-grp-
echo "-- lmdb data file after run 2:"
ls -la "$RUN/messages_db/" | grep -v lock
echo

echo "=========== enabling MySQL integration via /invalidate ==========="
curl -s -X POST -H "$ADMIN" \
  -d "{\"is_sql_integration_enabled\":true,\"db_host\":\"$DB_HOST\",\"db_port\":3306,\"db_user\":\"root\",\"db_password\":\"slpass\",\"db_name\":\"socketlink\"}" \
  localhost:8080/api/v1/invalidate; echo
sleep 2
echo "-- workers connected to MySQL: $(grep -c 'MySQL connected' /tmp/srv_persist.log)"
echo

echo "=========== RUN 3: cache rooms -> LMDB + MySQL writes ==========="
python3 "$SP/loadtest.py" --host 127.0.0.1 --port 8080 --no-tls $LOAD_ARGS --room-prefix pub-cache-grp-
echo
echo "-- flushing remaining MySQL batches:"
curl -s -H "$ADMIN" localhost:8080/api/v1/mysql/sync; echo
sleep 3
echo "-- final server metrics:"
curl -s -H "$ADMIN" localhost:8080/api/v1/metrics; echo
echo "-- lmdb data file after run 3:"
ls -la "$RUN/messages_db/" | grep -v lock

kill -TERM $SRVPID 2>/dev/null
sleep 2
kill -9 $SRVPID 2>/dev/null
echo "-- server log tail:"
tail -6 /tmp/srv_persist.log
