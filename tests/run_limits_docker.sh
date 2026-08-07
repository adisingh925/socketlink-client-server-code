#!/usr/bin/env bash
# run_limits_docker.sh — find the connection ceiling of the resource-capped
# server container by ramping connection counts until it OOMs, refuses, or the
# ramp stops completing. Uses build/loadgen (the C++ client) because the Python
# harness cannot hold this many connections on the same host.
#
# Assumes the container is already running, e.g.
#   docker run -d --name sl-server --cpus=1 --memory=1g \
#     --ulimit nofile=1048576:1048576 --network slnet -p 8080:8080 \
#     -e SL_THREADS=1 sl-server
# Restart it between ladders for a clean memory baseline.
set -u
SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SP/.." && pwd)"
LG="$REPO/build/loadgen"
DOCKER="${DOCKER:-/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe}"
ADMIN='api-key: change-me-admin-key'
STEPS="${STEPS:-20000 40000 60000 80000}"
RATE="${RATE:-1}"
SIZE="${SIZE:-64}"
DURATION="${DURATION:-10}"

ulimit -n 1048576 2>/dev/null || true

stat_mem()  { "$DOCKER" stats --no-stream --format "{{.MemUsage}}" sl-server 2>/dev/null | tr -d '\r'; }
stat_cpu()  { "$DOCKER" stats --no-stream --format "{{.CPUPerc}}" sl-server 2>/dev/null | tr -d '\r'; }
oomkilled() { "$DOCKER" inspect sl-server --format '{{.State.OOMKilled}}' 2>/dev/null | tr -d '\r'; }
running()   { "$DOCKER" inspect sl-server --format '{{.State.Status}}' 2>/dev/null | tr -d '\r'; }
srv_conns() {
  curl -s -m 5 -H "$ADMIN" localhost:8080/api/v1/metrics \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["connections"])' 2>/dev/null || echo "?"
}

echo "baseline: mem=$(stat_mem) status=$(running)"

for N in $STEPS; do
  echo "=================== $N connections ==================="
  "$LG" --conns "$N" --threads 64 --group 10 --rate "$RATE" --duration "$DURATION" \
        --size "$SIZE" --src-ips 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 --connect-timeout 300 --uid-prefix "lim${N}_" 2>&1 | grep -v '^\[loadgen\] connecting' &
  LGPID=$!

  # sample while the ramp + window run
  PEAK=0
  while kill -0 $LGPID 2>/dev/null; do
    sleep 3
    M=$(stat_mem)
    MB=$(echo "$M" | awk '{print $1}' | sed 's/MiB//;s/GiB/*1024/' | bc 2>/dev/null || echo 0)
    [ -n "$MB" ] && [ "${MB%.*}" -gt "${PEAK%.*}" ] 2>/dev/null && PEAK=$MB
    echo "   [sample] mem=$M cpu=$(stat_cpu) srv_conns=$(srv_conns) oom=$(oomkilled)"
  done
  wait $LGPID

  echo "   -> peak_mem_MiB≈$PEAK status=$(running) oom=$(oomkilled)"
  if [ "$(oomkilled)" = "true" ] || [ "$(running)" != "running" ]; then
    echo "!!! container died at $N connections (oom=$(oomkilled) status=$(running))"
    break
  fi
  sleep 5   # let connections fully close before the next step
done

echo "=================== final ==================="
echo "status=$(running) oom=$(oomkilled) mem=$(stat_mem)"
