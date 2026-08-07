#!/usr/bin/env bash
# vmstat.sh — one-line server + host snapshot, for polling during benchmarks.
M=$(curl -s -m 5 -H 'api-key: change-me-admin-key' localhost:8080/api/v1/metrics)
if [ -z "$M" ]; then
    echo "metrics: UNREACHABLE (server busy or down) | $(free -m | awk '/Mem:/{print $3"MB used"}') | load$(uptime | sed 's/.*load average://')"
    exit 0
fi
python3 - "$M" <<'PY'
import json, sys
m = json.loads(sys.argv[1])
print("conns={conns} deliveries={d} drops={dr} mem={mem}MiB paused={p} memrej={mr}".format(
    conns=m["connections"], d=m["messages_sent"], dr=m["dropped_messages"],
    mem=m["memory_working_set_bytes"] // 1048576, p=m["admission_paused"],
    mr=m["rejected_memory_pressure"]), end=" | ")
PY
free -m | awk '/Mem:/{printf "host %sMB used, %sMB avail | ", $3, $7}'
uptime | sed 's/.*load average: /load /'
