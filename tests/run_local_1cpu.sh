#!/usr/bin/env bash
# Local 1 CPU / 1 GB test of the plaintext (no-TLS) standalone server.
# Runs server + load generator in ONE WSL session so the VM is not torn down.
#
#   CONNS / PROCS / CONC / GROUP / RATE / DUR overridable via env.
set -u
D="$HOME/sl-deps"
REPO="/mnt/c/dev/socketlink-client-server-code"
CONNS="${CONNS:-20000}"; PROCS="${PROCS:-8}"; CONC="${CONC:-200}"
GROUP="${GROUP:-10}"; RATE="${RATE:-10}"; DUR="${DUR:-15}"; POOL="${POOL:-16}"
CORES="${CORES:-1}"                       # number of CPU cores (and worker threads)
CPUSET="0"; for ((i=1;i<CORES;i++)); do CPUSET="$CPUSET,$i"; done

cd "$D" || exit 1
mkdir -p messages_db; rm -f messages_db/*.mdb 2>/dev/null
pkill -9 -f "sl_local$" 2>/dev/null; sleep 1

echo "[test] starting server: $CORES core(s) (taskset -c $CPUSET), $CORES worker thread(s), MemoryMax=1G, plaintext :8080"
systemd-run --user --scope --unit=sltest -p MemoryMax=1G -p MemorySwapMax=0 \
  -- taskset -c "$CPUSET" env SL_THREADS="$CORES" "$D/sl_local" \
  > "$D/srv.log" 2>&1 &

for i in $(seq 1 40); do ss -ltn 2>/dev/null | grep -q :8080 && break; sleep 0.5; done
if ! ss -ltn 2>/dev/null | grep -q :8080; then
  echo "[test] SERVER FAILED TO LISTEN"; tail -15 "$D/srv.log"; exit 1
fi
echo "[test] server listening. log:"; tail -4 "$D/srv.log"

echo -n "[test] plaintext ping check: "
curl -s -m 5 -H "api-key: change-me-admin-key" "http://127.0.0.1:8080/api/v1/ping" && echo " <- OK" || echo " <- PING FAILED"

echo "[test] load: conns=$CONNS procs=$PROCS conc=$CONC group=$GROUP rate=$RATE dur=$DUR"
cd "$REPO" || exit 1
python3 tests/loadtest.py --host 127.0.0.1 --port 8080 --no-tls \
  --conns "$CONNS" --procs "$PROCS" --concurrency "$CONC" --pool "$POOL" \
  --group "$GROUP" --rate "$RATE" --duration "$DUR" 2>&1 | grep -vE "SSL connection is closed"

P=$(pgrep -f "sl_local$" | head -1)
if [ -n "$P" ]; then
  awk "/VmHWM/{printf \"[test] server PEAK rss = %.1f MB\n\", \$2/1024}" "/proc/$P/status"
  awk "/VmRSS/{printf \"[test] server now  rss = %.1f MB\n\", \$2/1024}" "/proc/$P/status"
  echo "[test] server ALIVE (pid=$P) — no crash/OOM"
else
  echo "[test] server GONE (crash or OOM-killed) — check srv.log:"; tail -8 "$D/srv.log"
fi
systemctl --user stop sltest.scope 2>/dev/null
pkill -9 -f "sl_local$" 2>/dev/null
echo "[test] done"
