#!/usr/bin/env bash
# stress_suite.sh [results-file] [scratch-dir] — adversarial stress suite against
# sl-server on slnet. Aimed at the failure modes found during hardening, not at
# throughput (that's sweep_matrix.sh):
#   A  the all-on 9.5KB flood + memory-pressure shedding that once segfaulted
#      (use-after-free in TopicTree::drain, fixed 9cb898d), sustained 30s @768MB
#   B  churn: 5 connect->publish->disconnect cycles on ONE server, 1500 cache-room
#      vacates per cycle (deferred-delete drain, memory ratchet)
#   C  2 workers, 400 STATE rooms, flood (cross-worker presence fan-out)
#   D  three concurrent clients (plain flood + cache rate20 + state rate10), all-on
#   E  60s soak, all-on, memory sampled for creep
# ~5 min. Server recreated per phase. Requires sl-server/sl-loadgen images and
# sl-mysql + sl-mock on slnet.
#
# Drain times are meaningful: the loadgen tears down with SO_LINGER{on,0} (RST),
# so the server learns of disconnects immediately. Before that fix, flood runs
# left FINs queued behind unsent data and "drain" measured the server's 120s
# idleTimeout, not its close path.
set -u
OUT="${1:-./stress_results.txt}"
TMPD="${2:-$(mktemp -d)}"
mkdir -p "$TMPD"; : > "$OUT"

CURL='docker run --rm --network slnet curlimages/curl:latest -s'
ADMIN='api-key: change-me-admin-key'
LG='docker run --rm --network slnet --ulimit nofile=1048576:1048576 sl-loadgen'

say() { echo "$@" | tee -a "$OUT"; }
metrics() { $CURL -H "$ADMIN" sl-server:8080/api/v1/metrics 2>/dev/null; }
mget() { local v; v=$(echo "$1" | tr ',' '\n' | grep "\"$2\"" | tr -dc '0-9'); echo "${v:-0}"; }
lgsum() { echo "$1" | sed -n 's/.*"connected": *\([0-9]*\).*"connect_failed": *\([0-9]*\).*"sent": *\([0-9]*\).*"recv": *\([0-9]*\).*"recv_rate_msgs_s": *\([0-9]*\).*/connected=\1 failed=\2 sent=\3 recv=\4 deliv_s=\5/p'; }

recreate() { # cpus mem threads
  docker rm -f sl-server >/dev/null 2>&1
  docker run -d --name sl-server --cpus="$1" --memory="$2" --ulimit nofile=1048576:1048576 \
    --sysctl net.ipv4.tcp_wmem="4096 8192 65536" --sysctl net.ipv4.tcp_rmem="4096 8192 65536" \
    --network slnet -p 8080:8080 -e SL_THREADS="$3" sl-server >/dev/null 2>&1
  local i; for i in $(seq 1 60); do [ -n "$(metrics)" ] && { sleep 0.5; return 0; }; sleep 0.3; done
  say "!! server did not become ready"
}
allon() {
  $CURL -X POST -H "$ADMIN" -d '{"is_sql_integration_enabled":true,"db_host":"sl-mysql","db_port":3306,"db_user":"root","db_password":"slpass","db_name":"socketlink","webhooks":126,"webhook_base_url":"sl-mock","webhook_path":"/hook","webhook_port":8443,"webhook_secret":"whsecret"}' sl-server:8080/api/v1/invalidate >/dev/null 2>&1
  sleep 1
}
# Working set (cgroup charge minus reclaimable file cache — the guard's own
# definition), sampled via docker exec: a curl container per sample is too slow
# to catch peaks under load (it produced one sample per ~4s and missed Phase E's
# creep window entirely).
wset() {
  docker exec sl-server sh -c 'c=$(cat /sys/fs/cgroup/memory.current); i=$(grep "^inactive_file " /sys/fs/cgroup/memory.stat | cut -d" " -f2); echo $((c-i))' 2>/dev/null
}
sample_mem() { # file seconds interval
  : > "$1"; local end=$((SECONDS+$2))
  while [ $SECONDS -lt $end ]; do local m; m=$(wset); [ -n "$m" ] && echo "$m" >> "$1"; sleep "$3"; done
}
peak_mib() { [ -s "$1" ] && echo $(( $(sort -n "$1" | tail -1) / 1048576 )) || echo 0; }
drain() { # wait for connections==0, print seconds taken
  local i c t0=$SECONDS
  for i in $(seq 1 150); do c=$(mget "$(metrics)" connections); [ "$c" = "0" ] && break; sleep 0.2; done
  echo "$((SECONDS-t0))s(conns=$c)"
}
report() { # label
  local m st errs pressure recovered paused
  m=$(metrics)
  st=$(docker inspect sl-server --format 'status={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}')
  errs=$(docker logs sl-server 2>&1 | grep -c '\[ERROR\]')
  pressure=$(docker logs sl-server 2>&1 | grep -c 'MEMORY PRESSURE')
  recovered=$(docker logs sl-server 2>&1 | grep -c 'Memory recovered')
  paused=$(echo "$m" | sed -n 's/.*"admission_paused": *\([a-z]*\).*/\1/p')
  say "RESULT|$1|$st|errors=$errs|pressureEvents=$pressure|recovered=$recovered|pausedNow=${paused:-n/a}"
  say "COUNTERS|$1|conns=$(mget "$m" connections) dropped=$(mget "$m" dropped_messages) shed=$(mget "$m" shed_connections) rejected=$(mget "$m" rejected_memory_pressure) lmdb=$(mget "$m" total_local_db_writes) sql=$(mget "$m" total_mysql_db_batch_writes) whok=$(mget "$m" total_success_webhook_calls) whfail=$(mget "$m" total_failed_webhook_calls) whdrop=$(mget "$m" dropped_webhook_events) dbdrop=$(mget "$m" dropped_db_rows) mem=$(( $(mget "$m" memory_working_set_bytes) / 1048576 ))MiB"
  echo "METRICS|$1|$m" >> "$OUT"
}

# ---- deps: mock + mysql must be up (they die with a Docker Desktop restart) ----
for c in sl-mock sl-mysql; do
  [ "$(docker inspect -f '{{.State.Running}}' $c 2>/dev/null)" = "true" ] || { say "starting $c"; docker start $c >/dev/null 2>&1; }
done
for i in $(seq 1 45); do docker run --rm --network slnet busybox sh -c 'nc -z sl-mysql 3306' >/dev/null 2>&1 && break; sleep 1; done
say "deps ready (mysql wait ${i}s)"

# ============ PHASE A: the once-fatal scenario, sustained ============
say ""; say "=== A: all-on 9.5KB FLOOD, 1 CPU / 768MB, 30s (memory-pressure shedding engages) ==="
recreate 1 768m 1; allon
sample_mem "$TMPD/memA" 36 1 &
LGA=$($LG --host sl-server --port 8080 --conns 5000 --threads 32 --group 10 --size 9500 --flood --duration 30 --prefix pub-cache-grp- --uid-prefix a_ 2>/dev/null | tr -d '\n' | tr -s ' ')
wait
say "LOADGEN|A|$(lgsum "$LGA")"
say "DRAIN|A|$(drain)"
sleep 1; $CURL -H "$ADMIN" sl-server:8080/api/v1/mysql/sync >/dev/null 2>&1; sleep 1
report A; say "PEAKMEM|A|$(peak_mib "$TMPD/memA")MiB"

# ============ PHASE B: churn — 5 cycles on the SAME server ============
say ""; say "=== B: churn, 5 x (3000 conns -> 1500 CACHE rooms -> full disconnect) on one server, 1 CPU / 1GB ==="
recreate 1 1g 1
for c in 1 2 3 4 5; do
  LGB=$($LG --host sl-server --port 8080 --conns 3000 --threads 32 --group 2 --size 1024 --rate 5 --duration 6 --prefix pub-cache-grp- --uid-prefix b${c}_ 2>/dev/null | tr -d '\n' | tr -s ' ')
  d=$(drain); m=$(metrics)
  say "CYCLE|B$c|$(lgsum "$LGB")|drain=$d|mem=$(( $(mget "$m" memory_working_set_bytes) / 1048576 ))MiB|errors=$(docker logs sl-server 2>&1 | grep -c '\[ERROR\]')"
done
report B

# ============ PHASE C: 2 workers, STATE rooms, flood ============
say ""; say "=== C: 2 workers, 400 STATE rooms (cross-worker presence fan-out), 1KB FLOOD, 20s ==="
recreate 2 1g 2
sample_mem "$TMPD/memC" 26 1 &
LGC=$($LG --host sl-server --port 8080 --conns 4000 --threads 32 --group 10 --size 1024 --flood --duration 20 --prefix pub-state-grp- --uid-prefix c_ 2>/dev/null | tr -d '\n' | tr -s ' ')
wait
say "LOADGEN|C|$(lgsum "$LGC")"; say "DRAIN|C|$(drain)"
report C; say "PEAKMEM|C|$(peak_mib "$TMPD/memC")MiB"

# ============ PHASE D: mixed concurrent workloads ============
say ""; say "=== D: 3 concurrent clients on one all-on server: plain FLOOD + cache rate20 + state rate10, 20s ==="
recreate 1 1g 1; allon
sample_mem "$TMPD/memD" 28 1 &
$LG --host sl-server --port 8080 --conns 2000 --threads 16 --group 10 --size 1024 --flood --duration 20 --prefix pub-grp- --uid-prefix d1_ 2>/dev/null | tr -d '\n' | tr -s ' ' > "$TMPD/lgD1" &
$LG --host sl-server --port 8080 --conns 1500 --threads 16 --group 5 --size 2048 --rate 20 --duration 20 --prefix pub-cache-grp- --uid-prefix d2_ 2>/dev/null | tr -d '\n' | tr -s ' ' > "$TMPD/lgD2" &
$LG --host sl-server --port 8080 --conns 1500 --threads 16 --group 10 --size 512 --rate 10 --duration 20 --prefix pub-state-grp- --uid-prefix d3_ 2>/dev/null | tr -d '\n' | tr -s ' ' > "$TMPD/lgD3" &
wait
say "LOADGEN|D-plain-flood|$(lgsum "$(cat "$TMPD/lgD1")")"
say "LOADGEN|D-cache-r20|$(lgsum "$(cat "$TMPD/lgD2")")"
say "LOADGEN|D-state-r10|$(lgsum "$(cat "$TMPD/lgD3")")"
say "DRAIN|D|$(drain)"
sleep 1; $CURL -H "$ADMIN" sl-server:8080/api/v1/mysql/sync >/dev/null 2>&1; sleep 1
report D; say "PEAKMEM|D|$(peak_mib "$TMPD/memD")MiB"

# ============ PHASE E: 60s soak, memory creep ============
say ""; say "=== E: 60s SOAK, all-on, 4000 conns rooms of 10, 1KB rate 10 (memory sampled for creep) ==="
recreate 1 1g 1; allon
sample_mem "$TMPD/memE" 66 2 &
LGE=$($LG --host sl-server --port 8080 --conns 4000 --threads 32 --group 10 --size 1024 --rate 10 --duration 60 --prefix pub-cache-grp- --uid-prefix e_ 2>/dev/null | tr -d '\n' | tr -s ' ')
wait
say "LOADGEN|E|$(lgsum "$LGE")"
creep=$(awk '{a[NR]=$1} END{n=NR; if(n<8){print "n/a"; exit} q=int(n/4); f=0; l=0; for(i=1;i<=q;i++)f+=a[i]; for(i=n-q+1;i<=n;i++)l+=a[i]; printf "first-quarter=%dMiB last-quarter=%dMiB delta=%+dMiB", f/q/1048576, l/q/1048576, (l/q-f/q)/1048576}' "$TMPD/memE")
say "CREEP|E|$creep"
say "DRAIN|E|$(drain)"
sleep 1; $CURL -H "$ADMIN" sl-server:8080/api/v1/mysql/sync >/dev/null 2>&1; sleep 1
report E; say "PEAKMEM|E|$(peak_mib "$TMPD/memE")MiB"

say ""; say "SUITE DONE -> $OUT"
