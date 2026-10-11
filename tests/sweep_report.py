#!/usr/bin/env python3
# sweep_report.py [results-file] — render sweep_matrix.sh output as a markdown
# table: loadgen throughput per run + server-side counter DELTAS (post - pre).
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "sweep_results.txt"
blocks, cur = [], {}
for line in open(path):
    line = line.rstrip("\n")
    if line == "---":
        if cur:
            blocks.append(cur)
            cur = {}
        continue
    if line.startswith("RUN|"):
        parts = line.split("|")
        cur["run"] = parts[1]
        cur["meta"] = dict(p.split("=", 1) for p in parts[2:] if "=" in p)
    elif line.startswith("LOADGEN|"):
        try:
            cur["lg"] = json.loads(line[len("LOADGEN|"):])
        except Exception:
            cur["lg"] = {}
    elif line.startswith("PRE|"):
        try:
            cur["pre"] = json.loads(line[len("PRE|"):])
        except Exception:
            cur["pre"] = {}
    elif line.startswith("POST|"):
        try:
            cur["post"] = json.loads(line[len("POST|"):])
        except Exception:
            cur["post"] = {}
if cur:
    blocks.append(cur)


def d(b, k):
    return b.get("post", {}).get(k, 0) - b.get("pre", {}).get(k, 0)


def persist(meta):
    if meta.get("prefix", "").startswith("pub-cache"):
        return "LMDB+SQL" if meta.get("mysql") == "1" else "LMDB"
    return "plain"


hdr = ["run", "room", "payload", "rate", "persist", "wh",
       "conns", "send/s", "deliver/s", "MB/s", "dropMsg",
       "LMDBw", "SQLw", "WHok", "WHfail", "WHdrop", "DBdrop", "memMiB", "paused"]
rows = []
for b in blocks:
    m, lg = b.get("meta", {}), b.get("lg", {})
    post = b.get("post", {})
    rows.append([
        b.get("run", "?"),
        m.get("group", "?"),
        (m.get("size", "?") + "B"),
        m.get("rate", "?"),
        persist(m),
        "on" if m.get("wh") == "1" else "off",
        str(lg.get("connected", "?")),
        f"{lg.get('send_rate_msgs_s', 0):,}",
        f"{lg.get('recv_rate_msgs_s', 0):,}",
        f"{lg.get('recv_MB_s', 0):.1f}",
        f"{d(b, 'dropped_messages'):,}",
        f"{d(b, 'total_local_db_writes'):,}",
        f"{d(b, 'total_mysql_db_batch_writes'):,}",
        f"{d(b, 'total_success_webhook_calls'):,}",
        f"{d(b, 'total_failed_webhook_calls'):,}",
        f"{d(b, 'dropped_webhook_events'):,}",
        f"{d(b, 'dropped_db_rows'):,}",
        f"{post.get('memory_working_set_bytes', 0) / 1048576:.0f}",
        "YES" if post.get("admission_paused") else "no",
    ])

print("| " + " | ".join(hdr) + " |")
print("|" + "|".join("---" for _ in hdr) + "|")
for r in rows:
    print("| " + " | ".join(r) + " |")
print(f"\n{len(rows)} runs parsed.")
