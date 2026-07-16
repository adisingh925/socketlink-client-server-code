#!/usr/bin/env bash
# Find the limits of the plaintext server on 1 CPU / 1 GB.
# Starts ONE server (1 core, 1 worker thread, MemoryMax=1G) and drives escalating
# loads in a single WSL session. Two sweeps:
#   A) THROUGHPUT: fixed conns, rising fan-out/rate -> find deliveries/s ceiling (drops).
#   B) CONNECTIONS: rising conn count, minimal traffic -> find memory ceiling (OOM).
set -u
D="$HOME/sl-deps"; REPO="/mnt/c/dev/socketlink-client-server-code"
cd "$D" || exit 1
mkdir -p messages_db; rm -f messages_db/*.mdb 2>/dev/null
pkill -9 -f "sl_local$" 2>/dev/null; sleep 1

echo "=== starting server: 1 core, 1 thread, MemoryMax=1G, plaintext :9001 ==="
systemd-run --user --scope --unit=sltest -p MemoryMax=1G -p MemorySwapMax=0 \
  -- taskset -c 0 env SL_CONFIG="$D/config.json" SL_THREADS=1 "$D/sl_local" \
  > "$D/srv.log" 2>&1 &
for i in $(seq 1 40); do ss -ltn 2>/dev/null | grep -q :9001 && break; sleep 0.5; done
ss -ltn 2>/dev/null | grep -q :9001 || { echo "SERVER FAILED"; tail "$D/srv.log"; exit 1; }
SRVPID=$(pgrep -f "sl_local$" | head -1)
echo "server pid=$SRVPID listening"

run() { # label conns procs conc pool group rate dur
  local label="$1"; shift
  local conns="$1" procs="$2" conc="$3" pool="$4" group="$5" rate="$6" dur="$7"
  echo ""; echo "----- $label: conns=$conns group=$group rate=$rate dur=${dur}s -----"
  cd "$REPO"
  python3 tests/loadtest.py --host 127.0.0.1 --port 9001 --no-tls \
    --conns "$conns" --procs "$procs" --concurrency "$conc" --pool "$pool" \
    --group "$group" --rate "$rate" --duration "$dur" 2>&1 \
    | grep -vE "socket\.send\(\) raised exception|SSL connection is closed" \
    | grep -E '"connected"|recv_rate_msgs_s|messages_sent_local_only|dropped_messages|payload_MB_s|connections_reported'
  cd "$D"
  local P; P=$(pgrep -f "sl_local$" | head -1)
  if [ -z "$P" ]; then echo ">>> SERVER DIED (OOM/crash) at $label"; tail -5 "$D/srv.log"; return 1; fi
  awk "/VmHWM/{printf \">>> server peak rss = %.1f MB\n\", \$2/1024}" "/proc/$P/status"
  return 0
}

echo ""; echo "########## SWEEP A: THROUGHPUT (fan-out group=100, rising rate) ##########"
run "A1 rate2"  6000 8 15 96 100 2  8 || true
run "A2 rate5"  6000 8 15 96 100 5  8 || true
run "A3 rate10" 6000 8 15 96 100 10 8 || true
run "A4 rate20" 6000 8 15 96 100 20 8 || true

echo ""; echo "########## SWEEP B: CONNECTIONS (rate=1, rising count -> memory ceiling) ##########"
for N in 20000 40000 60000 80000 100000; do
  run "B $N" "$N" 8 18 128 10 1 5 || { echo "### stopping connection sweep: server gone at N=$N ###"; break; }
done

echo ""; echo "=== final server state ==="
P=$(pgrep -f "sl_local$" | head -1)
if [ -n "$P" ]; then
  awk "/VmHWM/{printf \"server ALIVE, peak rss = %.1f MB\n\", \$2/1024}" "/proc/$P/status"
else
  echo "server GONE (last run OOM/crashed) — srv.log tail:"; tail -6 "$D/srv.log"
fi
systemctl --user stop sltest.scope 2>/dev/null; pkill -9 -f "sl_local$" 2>/dev/null
echo "=== sweep done ==="
