#!/usr/bin/env bash
# sweep_matrix.sh [results-file] — structured benchmark sweep (OFAT + stress combos)
# against sl-server (1 CPU / 1 GB) on the slnet docker network.
#
# One-factor-at-a-time from a baseline (group 10, 1 KB, rate 5, plain rooms,
# webhooks off) so each dimension's cost is isolated, plus combined worst-case
# points. ~17 runs, ~10-15 min. Format results with: python3 sweep_report.py <file>
#
# The server container is RECREATED per run: a single long-lived 1-CPU server
# degrades over many back-to-back 5k-connection runs (cumulative socket churn
# left later runs unable to connect — measured connect_failed ~2.9k from run 4
# onward), and recreation also gives clean per-run counters and memory.
#
# Requires: sl-server + sl-loadgen images, sl-mysql and sl-mock running on slnet
# (see run_persistence_loadtest.sh / run_webhook_loadtest.sh headers for their
# docker run lines). MySQL fires only for pub-cache-* rooms.
set -u

OUT="${1:-./sweep_results.txt}"
: > "$OUT"

CURL='docker run --rm --network slnet curlimages/curl:latest -s'
ADMIN='api-key: change-me-admin-key'
LG='docker run --rm --network slnet --ulimit nofile=1048576:1048576 sl-loadgen'
CONNS="${CONNS:-5000}"
THREADS="${THREADS:-32}"
DUR="${DUR:-12}"

metrics() { $CURL -H "$ADMIN" sl-server:8080/api/v1/metrics 2>/dev/null; }

recreate_server() {
  docker rm -f sl-server >/dev/null 2>&1
  docker run -d --name sl-server --cpus=1 --memory=1g --ulimit nofile=1048576:1048576 \
    --sysctl net.ipv4.tcp_wmem="4096 8192 65536" --sysctl net.ipv4.tcp_rmem="4096 8192 65536" \
    --network slnet -p 8080:8080 -e SL_THREADS=1 sl-server >/dev/null 2>&1
  local i
  for i in $(seq 1 60); do
    [ -n "$(metrics)" ] && { sleep 0.5; return 0; }
    sleep 0.3
  done
  echo "  !! server did not become ready"
}

setcfg() { # $1=mysql(0/1) $2=webhooks(0/1) — explicit both ways, no carryover
  local sql="false"; [ "$1" = "1" ] && sql="true"
  local whbits=0; [ "$2" = "1" ] && whbits=126
  $CURL -X POST -H "$ADMIN" -d "{\"is_sql_integration_enabled\":$sql,\"db_host\":\"sl-mysql\",\"db_port\":3306,\"db_user\":\"root\",\"db_password\":\"slpass\",\"db_name\":\"socketlink\",\"webhooks\":$whbits,\"webhook_base_url\":\"sl-mock\",\"webhook_path\":\"/hook\",\"webhook_port\":8443,\"webhook_secret\":\"whsecret\"}" \
    sl-server:8080/api/v1/invalidate >/dev/null 2>&1
  sleep 1
}

# label|group|size|rate|prefix|mysql|webhooks    (rate "flood" => --flood)
# NOTE on payload: the server's maxPayloadLength is 10240 for the WHOLE frame;
# a 10240-byte body plus the {"rid":...,"message":...} envelope exceeds it and
# is (correctly) rejected, so the large-payload runs use 9500-byte bodies.
RUNS=(
  "baseline|10|1024|5|pub-grp-|0|0"
  "room2|2|1024|5|pub-grp-|0|0"
  "room100|100|1024|5|pub-grp-|0|0"
  "payload100|10|100|5|pub-grp-|0|0"
  "payload9500|10|9500|5|pub-grp-|0|0"
  "rate1|10|1024|1|pub-grp-|0|0"
  "rate20|10|1024|20|pub-grp-|0|0"
  "flood|10|1024|flood|pub-grp-|0|0"
  "lmdb|10|1024|5|pub-cache-grp-|0|0"
  "mysql|10|1024|5|pub-cache-grp-|1|0"
  "webhooks|10|1024|5|pub-grp-|0|1"
  "stress_all_heavy|10|9500|flood|pub-cache-grp-|1|1"
  "stress_all_mod|10|1024|20|pub-cache-grp-|1|1"
  "grp2_flood|2|1024|flood|pub-grp-|0|0"
  "grp100_flood|100|1024|flood|pub-grp-|0|0"
  "wh_flood|10|1024|flood|pub-grp-|0|1"
  "lmdb_flood|10|1024|flood|pub-cache-grp-|0|0"
)

i=0
for spec in "${RUNS[@]}"; do
  IFS='|' read -r label group size rate prefix mysql wh <<< "$spec"
  i=$((i+1))
  echo ">>> [$i/${#RUNS[@]}] $label  group=$group size=$size rate=$rate prefix=$prefix mysql=$mysql wh=$wh"

  recreate_server
  setcfg "$mysql" "$wh"

  rateflag="--rate $rate"; [ "$rate" = "flood" ] && rateflag="--flood"

  PRE="$(metrics)"
  LGOUT="$($LG --host sl-server --port 8080 --conns $CONNS --threads $THREADS \
      --group $group --size $size $rateflag --duration $DUR \
      --prefix "$prefix" --uid-prefix "u${i}_" 2>/dev/null)"
  sleep 2
  [ "$mysql" = "1" ] && { $CURL -H "$ADMIN" sl-server:8080/api/v1/mysql/sync >/dev/null 2>&1; sleep 1; }
  POST="$(metrics)"

  conn=$(echo "$LGOUT" | tr -d '\n' | sed -n 's/.*"connected": *\([0-9]*\).*/\1/p')
  echo "    connected=$conn"
  {
    echo "RUN|$label|group=$group|size=$size|rate=$rate|prefix=$prefix|mysql=$mysql|wh=$wh"
    echo "LOADGEN|$(echo "$LGOUT" | tr -d '\n' | tr -s ' ')"
    echo "PRE|$PRE"
    echo "POST|$POST"
    echo "---"
  } >> "$OUT"
done
echo "DONE -> $OUT   (format: python3 tests/sweep_report.py $OUT)"
