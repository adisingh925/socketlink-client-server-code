#!/usr/bin/env bash
# run_max_connections.sh — how many IDLE connections one server can hold.
#
# No messages at all: connect, answer keepalive pings, hold. This isolates
# connection capacity (memory + fd + accept cost) from message throughput, and
# it is the number that matters for presence/notification workloads where
# sockets vastly outnumber messages.
#
# Steps the target upward and stops at the first level the server cannot hold,
# reporting the last good one. A level counts as HELD when the server's own
# `connections` metric reaches >= 98% of the target and the container is still
# alive after a hold period.
#
#   bash tests/run_max_connections.sh                  # default 1 CPU / 1 GB
#   CPUS=2 MEM=2g STEPS="50000 100000" bash tests/run_max_connections.sh
#
# By default the connection cap is taken out of the picture (a low
# SL_BYTES_PER_CONN and a high SL_MAX_CONNECTIONS) so the result is the physical
# ceiling — memory, with the guard as backstop. Set CAP_DEFAULTS=1 to instead
# measure what the server admits out of the box.
set -u
SP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER="${DOCKER:-/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe}"
ADMIN='api-key: change-me-admin-key'

CPUS="${CPUS:-1}"
MEM="${MEM:-1g}"
THREADS="${THREADS:-1}"
STEPS="${STEPS:-20000 40000 60000 80000 100000}"
HOLD="${HOLD:-45}"          # seconds to hold each level before judging it
PER_CLIENT="${PER_CLIENT:-50000}"   # connections per client container
CAP_DEFAULTS="${CAP_DEFAULTS:-0}"

if [ "$CAP_DEFAULTS" = "1" ]; then
    CAP_ENV=""
    MODE="server defaults (adaptive cap decides)"
else
    CAP_ENV="-e SL_BYTES_PER_CONN=4096 -e SL_MAX_CONNECTIONS=2000000 -e SL_MIN_BYTES_PER_CONN=5120"
    MODE="cap raised (physical ceiling; guard is the backstop)"
fi

cleanup_clients() {
    for c in $("$DOCKER" ps -aq --filter "name=sl-mc" 2>/dev/null | tr -d '\r'); do
        "$DOCKER" rm -f "$c" >/dev/null 2>&1
    done
}

srv_conns() {
    curl -s -m 8 -H "$ADMIN" localhost:8080/api/v1/metrics 2>/dev/null \
        | tr ',' '\n' | grep '"connections"' | tr -dc '0-9'
}

srv_field() {
    curl -s -m 8 -H "$ADMIN" localhost:8080/api/v1/metrics 2>/dev/null \
        | tr ',' '\n' | grep "\"$1\"" | tr -dc '0-9'
}

echo "max IDLE connections: ${CPUS} CPU / ${MEM}, SL_THREADS=${THREADS}"
echo "mode: $MODE"
echo

BEST=0
for N in $STEPS; do
    cleanup_clients
    "$DOCKER" rm -f sl-server >/dev/null 2>&1
    # shellcheck disable=SC2086
    "$DOCKER" run -d --name sl-server --cpus="$CPUS" --memory="$MEM" \
        --ulimit nofile=1048576:1048576 \
        --sysctl net.ipv4.tcp_wmem="4096 8192 65536" \
        --sysctl net.ipv4.tcp_rmem="4096 8192 65536" \
        --network slnet -p 8080:8080 -e SL_THREADS="$THREADS" $CAP_ENV sl-server >/dev/null
    sleep 3

    CLIENTS=$(( (N + PER_CLIENT - 1) / PER_CLIENT ))
    PER=$(( N / CLIENTS ))
    echo "=== target $N ($CLIENTS client container(s) x $PER) ==="

    for i in $(seq 1 "$CLIENTS"); do
        "$DOCKER" run -d --name "sl-mc$i" --network slnet \
            --ulimit nofile=1048576:1048576 \
            --sysctl net.ipv4.ip_local_port_range="1024 65535" sl-loadgen \
            --host sl-server --port 8080 --conns "$PER" --threads 48 \
            --idle --no-subscribe --duration "$HOLD" --connect-timeout 300 \
            --uid-prefix "mc${i}n${N}_" >/dev/null
    done

    # watch the ramp, then judge the level
    PEAK=0
    OOM=false
    for t in $(seq 1 $(( (HOLD + 60) / 10 )) ); do
        sleep 10
        OOM=$("$DOCKER" inspect sl-server --format '{{.State.OOMKilled}}' 2>/dev/null | tr -d '\r')
        [ "$OOM" = "true" ] && break
        C=$(srv_conns)
        C=${C:-0}
        [ "$C" -gt "$PEAK" ] 2>/dev/null && PEAK=$C
        MEMMIB=$(( $(srv_field memory_working_set_bytes || echo 0) / 1048576 ))
        printf "    t+%-3ss conns=%-8s peak=%-8s mem=%sMiB\n" "$((t*10))" "$C" "$PEAK" "$MEMMIB"
    done

    STATUS=$("$DOCKER" inspect sl-server --format '{{.State.Status}}' 2>/dev/null | tr -d '\r')
    REJ=$(srv_field rejected_memory_pressure); REJ=${REJ:-0}
    CAP=$(srv_field connection_limit); CAP=${CAP:-?}
    THRESH=$(( N * 98 / 100 ))

    if [ "$OOM" = "true" ] || [ "$STATUS" != "running" ]; then
        echo "    -> FAILED at $N (oom=$OOM status=$STATUS, peak $PEAK)"
        break
    elif [ "$PEAK" -ge "$THRESH" ]; then
        echo "    -> HELD $PEAK (cap=$CAP, memory-pressure rejections=$REJ)"
        BEST=$PEAK
    else
        echo "    -> SHORT: peaked at $PEAK of $N (cap=$CAP, rejections=$REJ) — this is the limit"
        [ "$PEAK" -gt "$BEST" ] && BEST=$PEAK
        break
    fi
done

cleanup_clients
echo
echo "==================================================="
echo " max idle connections held: $BEST  (${CPUS} CPU / ${MEM})"
echo "==================================================="
