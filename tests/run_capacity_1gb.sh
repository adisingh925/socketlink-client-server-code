#!/usr/bin/env bash
# run_capacity_1gb.sh — pure WebSocket pub/sub capacity of one 1 CPU / 1 GB
# container. No MySQL, no webhooks, no LMDB (plain pub-grp-* rooms never touch
# the message store — verified by total_local_db_writes staying 0).
#
# Server is recreated before each phase so memory/counters start clean.
set -u
DOCKER="${DOCKER:-/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe}"
ADMIN='api-key: change-me-admin-key'

server_up() {
  "$DOCKER" rm -f sl-server >/dev/null 2>&1
  "$DOCKER" run -d --name sl-server --cpus=1 --memory=1g \
    --ulimit nofile=1048576:1048576 \
    --sysctl net.ipv4.tcp_wmem="4096 8192 65536" \
    --sysctl net.ipv4.tcp_rmem="4096 8192 65536" \
    --network slnet -p 8080:8080 -e SL_THREADS=1 sl-server >/dev/null
  sleep 3
}

metrics() { curl -s -m 8 -H "$ADMIN" localhost:8080/api/v1/metrics; }

report() {
  metrics | python3 -c '
import json,sys
m=json.load(sys.stdin)
print("    server: deliveries={:,} drops={:,} lmdb={} mysql={} webhooks={} mem={}MiB paused={}".format(
    m["messages_sent"], m["dropped_messages"], m["total_local_db_writes"],
    m["total_mysql_db_batch_writes"], m["total_success_webhook_calls"],
    m["memory_working_set_bytes"]//1048576, m["admission_paused"]))'
}

# client container; args passed through to loadgen
drive() {
  "$DOCKER" run --rm --network slnet --ulimit nofile=1048576:1048576 \
    --sysctl net.ipv4.ip_local_port_range="1024 65535" sl-loadgen \
    --host sl-server --port 8080 "$@" 2>/dev/null \
    | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("    client: conns={:,} sent/s={:,.0f} recv/s={:,.0f} MB/s={} ({:,} failed)".format(
    d["connected"], d["send_rate_msgs_s"], d["recv_rate_msgs_s"], d["recv_MB_s"], d["connect_failed"]))'
}

echo "############ PHASE 1: fan-out throughput (rooms of 100) ############"
for R in 1 2 3; do
  server_up
  echo "--- rate=$R/conn  (offered $((5000*R*99)) deliveries/s)"
  drive --conns 5000 --threads 32 --group 100 --rate $R --duration 15 --size 256 --uid-prefix p1r${R}_
  report
done

echo "############ PHASE 2: payload size sweep (rooms of 10) ############"
for S in 64 1024 10000; do
  server_up
  echo "--- payload=${S}B"
  drive --conns 5000 --threads 32 --group 10 --rate 5 --duration 15 --size $S --uid-prefix p2s${S}_
  report
done

echo "############ PHASE 3: connection capacity (clamp is ~21,299) ############"
for N in 10000 20000; do
  server_up
  echo "--- $N connections"
  drive --conns $N --threads 64 --group 10 --rate 1 --duration 20 --size 128 --connect-timeout 180 --uid-prefix p3n${N}_
  report
done

echo "############ PHASE 4: overload (2x the cap, sustained) ############"
server_up
echo "--- 45,000 attempted vs ~21,299 cap"
drive --conns 45000 --threads 64 --group 10 --rate 2 --duration 30 --size 256 --connect-timeout 180 --uid-prefix p4_
report
echo "--- container survived: oom=$("$DOCKER" inspect sl-server --format '{{.State.OOMKilled}}' | tr -d '\r') status=$("$DOCKER" inspect sl-server --format '{{.State.Status}}' | tr -d '\r')"
