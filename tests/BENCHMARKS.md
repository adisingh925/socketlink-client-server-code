# Benchmark methodology and results

All numbers below were measured on one machine (WSL2 Ubuntu 24.04, 20 cores, 15 GB
RAM) with the load client **co-located** with the server, so every figure is a
*lower bound* on server capability — see [Caveats](#caveats).

Two deployment targets are measured:

- **native** — `build/socketlink` run directly in WSL, `SL_THREADS` unset (20 workers)
- **docker** — the same binary in its container, capped at 1 CPU / 1 GB:
  `docker run -d --name sl-server --cpus=1 --memory=1g --ulimit nofile=1048576:1048576 --network slnet -p 8080:8080 -e SL_THREADS=1 sl-server`

> The server under test now always runs in the container. Refresh it after every
> build: `cp build/socketlink docker/socketlink && docker build -t sl-server docker/`
> then **recreate** (not restart) the container — restarting keeps the old binary.

## Tooling

| Tool | What it is | Key flags |
|---|---|---|
| `tests/loadtest.py` | Multi-process asyncio client (GIL-bound; the historical bottleneck) | `--conns --procs --group --rate --duration --size --room-prefix --no-tls --src-ips` |
| `build/loadgen` (`make loadgen`) | C++ epoll client, pre-masked frames, streaming parser | `--conns --threads --group --rate/--flood --duration --size --prefix` |
| `tests/wsclient.py` | Functional suite: echo, JSON escaping, latency, 40-sub fan-out | positional `host port label` |
| `tests/run_persistence_loadtest.sh` | 3 runs: plain / LMDB / LMDB+MySQL | — |
| `tests/run_webhook_loadtest.sh` | Dispatcher + verification pool + drain + deny path | — |

`--rate` is **per connection**, so offered ingress = `conns × rate` and offered
fan-out = `conns × rate × (group − 1)`.

## Metrics collected

**Client side** — `sent`, `recv`, `send_rate_msgs_s`, `recv_rate_msgs_s`, `recv_MB_s`.

**Server** (`GET /api/v1/metrics`, admin key) — `connections`, `messages_sent`
(true cross-worker deliveries), `total_payload_sent`, `dropped_messages`,
`total_local_db_writes` (LMDB), `total_mysql_db_batch_writes`,
`total_success_webhook_calls` / `total_failed_webhook_calls`, `dropped_log_lines`,
`dropped_webhook_events`, `dropped_db_rows`, `average_latency`.

**Container** — `docker stats` CPU% / MEM, plus `docker inspect … .State.OOMKilled`.

**External ground truth** (independent of the server's own counters):
mock webhook's request counter, `SELECT COUNT(*)` in MySQL, and LMDB read-back
through `GET /api/v1/messages/room/:rid`.

**Correctness invariant** used throughout: with rooms of size *N* and no echo to
the publisher, `recv` must equal `(N−1) × sent`. Every "lossless" claim below is
that identity holding exactly.

## Core throughput

Command shape: `loadtest.py --conns 20000 --procs 16 --group 10 --rate 5 --duration 15 --size <S> --no-tls`

| Target | Payload | Deliveries/s | Bandwidth | Drops |
|---|---|---|---|---|
| native | 1 B | 681,331 | 33 MB/s | 0 |
| native | 1 KB | 656,994 | 704 MB/s | 0 |
| docker 1cpu (5k conns) | 1 KB | 224,980 | 241 MB/s | 0 (69% CPU, 386 MiB) |

## Multi-core scaling (corrected) and the profile

Earlier notes claimed per-core efficiency fell past 4 cores (404k→303k del/s).
**That was a measurement artifact** — a single `loadgen` container cannot
saturate 8 server cores, so the 8-core figure was client-limited. Re-measured
with the client count scaled to the cores (saturated, rooms of 10, 128 B):

| Cores | Deliveries/s | Per core |
|---|---|---|
| 1 | 449,561 | 449,561 |
| 2 | 1,025,841 | 512,920 |
| 4 | 2,258,962 | 564,740 |
| 8 | 4,426,253 | 553,281 |

Scaling is essentially **linear through 8 cores** at ~550k deliveries/s per core;
there is no decline. (The 1-core row is lower per-core only because at this
saturated rate one core also carries accept/admin work; its gentle-load knee is
~1.0M — see the overload section.)

### What the profile shows (perf, saturated)

Runnable at last via a privileged `perf` sidecar container sharing the server's
PID namespace (`--pid=container:sl-server --privileged`), which sidesteps the
restricted host `ptrace_scope` and the missing distro package.

- **~89% of CPU is the `sendto`/`tcp_sendmsg` transmit path.** The server is
  send-syscall bound; userspace (parse, JSON escape, publish) is under ~10%.
  This is why ingress shedding could not help — there is almost no userspace CPU
  to reclaim — and why the overload plateau is a kernel property.
- **~5–6% is Docker's `nft_do_chain` + conntrack**, per packet, on the bridge
  network. Every benchmark here pays that NAT tax; a host-network / behind-LB
  production deployment would not, so these figures are conservative.
- At 8 cores the only notable userspace costs are the cross-worker defer (~7%)
  and the fan-out `shared_ptr` refcount release (~3%); the latter was halved by
  merging rid+payload into one allocation (see git log).

## Capacity per deployment size (post-OOM-fix, protections active)

Rooms of 100, 256-byte bodies, measured with `loadgen` client containers on the
docker network. "Lossless" = server `dropped_messages` delta of ~0.

| Deployment | Connection cap (self-clamped) | Lossless deliveries/s | Bandwidth | Saturates at |
|---|---|---|---|---|
| 1 CPU / 1 GB container | 21,299 | **987,198** | 298 MB/s | ~1.5M offered → sheds |
| 4 CPU / 4 GB container | 99,942 | **2,962,711** (51 drops in 44.4M) | 894 MB/s | ~2.33M sustained plateau |
| 20-core native (no cgroup limit) | — | 7,790,000 | 2.35 GB/s | ~8.4M |

The 4- and 20-core rows here were measured with a single client and are
client-limited; the corrected multi-core section above shows scaling is actually
~linear at ~550k deliveries/s per core through 8 cores, bound by the per-delivery
`send()` syscall. Capping `SO_SNDBUF` cost **no** throughput: the 1-CPU container
measured 989,294 deliveries/s before the fix and 987,198 after, with memory
dropping from hundreds of MiB to 14 MiB at the same load.

## Pure WebSocket pub/sub — one 1 CPU / 1 GB container

`tests/run_capacity_1gb.sh`. No MySQL, no webhooks, no LMDB (plain `pub-grp-*`
rooms never touch the store — confirmed by `total_local_db_writes` = 0 in every
phase). Fresh container per phase; `loadgen` client container on `slnet`.

**Fan-out ceiling** (5,000 connections, rooms of 100, 256 B):

| Offered | Delivered | Bandwidth | Drops |
|---|---|---|---|
| 495k/s | 493,489/s | 149 MB/s | **0** |
| 990k/s | **987,517/s** | **298 MB/s** | **0** ← lossless ceiling |
| 1.49M/s | 201,375/s | 61 MB/s | 76,853 (saturated) |

**Payload sweep** (5,000 connections, rooms of 10, 225k deliveries/s offered):

| Payload | Delivered | Bandwidth | Drops |
|---|---|---|---|
| 64 B | 224,914/s | 25 MB/s | 0 |
| 1 KB | 224,912/s | 241 MB/s | 0 |
| 10 KB | 69,605/s | **699 MB/s** | 112,904 (bandwidth-bound) |

64 B and 1 KB deliver at an *identical* message rate — proof the cost is
per-message (the `send()` syscall), not per-byte, until bandwidth binds at 10 KB.

**Connections and overload:**

| Test | Result | Memory |
|---|---|---|
| 10,000 connections | 0 drops | 21 MiB |
| 20,000 connections | 0 drops | 41 MiB |
| **45,000 attempted** | exactly **21,299 admitted** (the self-clamp), 23,701 rejected, 376,505 deliveries/s, **0 drops**, `OOMKilled=false` | 40 MiB |

Note how cheap *lightly loaded* connections are: 20k cost 41 MiB (~2 KB each),
versus the ~40 KB the clamp budgets for a connection under heavy fan-out. The
clamp is deliberately sized for the worst case. For a light-traffic workload
(chat presence, notifications) you can raise the ceiling by lowering the
estimate — `SL_BYTES_PER_CONN=8192` yields a ~106k cap on 1 GB — but only if you
are confident the fan-out stays light, because the memory it protects against is
the kind admission control cannot reclaim.

## Max idle connections (no messages at all)

`tests/run_max_connections.sh` — connect, answer keepalive pings, hold; nothing
is ever published and no room is subscribed. This is the number that matters for
presence/notification workloads where sockets vastly outnumber messages. A level
counts as held only when the SERVER's own `connections` metric reaches the
target and the container survives the hold.

On **1 CPU / 1 GB**:

| Configuration | Max held | Memory | Limited by |
|---|---|---|---|
| **server defaults** | **60,915** | 303 MiB (30%) | the adaptive cap's safety floor |
| floor lowered to the measured cost (`SL_MIN_BYTES_PER_CONN=5120`) | **135,528** | 686 MiB (67%) | memory |

A bare idle connection costs **~5 KB** (80k → 399 MiB, 110k → 555 MiB,
135k → 686 MiB) — less than half the ~11.7 KB of a connection that has joined a
room and carries light traffic.

**Why the default stops at 61k when memory is only 30% used.** The adaptive cap
refuses to assume a per-connection cost below 12 KB even when it measures 5 KB,
because *idle is not a promise*: if those sockets start carrying fan-out they
cost ~40 KB each, and 135k of them would need 5.4 GB — while admission control
can refuse a new connection but can never take back one already granted. The
floor is what stops the server writing a cheque its memory cannot honour later.

`SL_MIN_BYTES_PER_CONN` lowers it for a workload known to stay idle. That is a
deliberate trade: it roughly doubles capacity and removes the margin that
protects against those connections waking up.

## Overload behaviour past the ceiling (1 CPU / 1 GB, rooms of 10, 128 B)

Stepping the offered rate through the ceiling:

| Offered/s | Delivered/s | |
|---|---|---|
| 864,000 | 863,426 | lossless |
| 1,008,000 | 1,006,998 | lossless (the knee) |
| 1,152,000 | 421,213 | past the knee |
| 1,728,000 | 442,859 | |
| 2,880,000 | 465,518 | |
| 5,760,000 | 422,205 | 5.7× overload |

So the knee is ~1.0M deliveries/s, and past it delivery drops sharply to a
**stable ~440k plateau** that holds from 1.3× to 5.7× overload — the server does
NOT spiral toward zero under load, it settles at ~44% of its knee throughput and
stays there no matter how hard it is pushed.

**Ingress shedding was tried here and REJECTED.** The hypothesis was that at
saturation the CPU spent parsing and publishing messages that then hit full
socket buffers was stolen from delivery, so dropping excess before the parse
would lift the plateau. Measured, it did the opposite: shedding cut delivery from
570k to 453k at rate 16 (and a *silent* shed that sent no notice was no better,
ruling out the extra notice-sends). Parsing was not competing with delivery for
CPU — dropping ingress just discards messages that would have been delivered. The
plateau is set by socket-buffer / TCP delivery dynamics under saturation, not by
wasted application CPU, and is not improvable from application code. The change
was reverted.

The one genuine inefficiency — the plateau sitting at ~44% of the knee rather
than holding near it — lives in the kernel/uWS write path and would need work
there, not in this server.

## Idle connection capacity with light traffic (one core)

Essentially-idle connections (0.02 msgs/s each, so keepalive pings dominate).
Cost is consistently **~11.7 KB per idle connection**, so RAM decides until the
core saturates.

| Config | Connections held | Memory | CPU | Bound by |
|---|---|---|---|---|
| 1 CPU / 1 GB | **55,517** | 640 MiB (62%) | 0–104% | memory (adaptive cap) |
| 1 CPU / 4 GB | 100,000 | 1,157 MiB | 61–72% | the configured 100k cap |
| 1 CPU / 6 GB | **200,000** | 2,338 MiB | ~112% (saturated) | **CPU** |

So one core tops out around **200k idle connections**, and below that RAM is the
constraint: budget ~12 KB each. Ramp rate was ~6,250 connections/s on one core.

The 1 GB row is the adaptive cap working as intended: it measured 13 KiB/conn and
raised the limit from the 21,299 static default to 55,517 — 2.6× — because idle
connections genuinely are cheaper than the worst-case estimate. The same server
under heavy fan-out shrinks back to ~21k. `SL_MAX_CONNECTIONS` sets the ceiling
the adaptive cap may grow toward (default 100,000).

## Ceilings (C++ `loadgen`, rooms of 100)

| Target | Command | Delivered | Bandwidth | Drops |
|---|---|---|---|---|
| native | `--conns 10000 --threads 16 --group 100 --rate 8 --duration 15 --size 256` | **7.79M/s** | 2.35 GB/s | 2,106 / 118.8M (0.0018%) |
| native | same, `--rate 20` | 8.41M/s | 2.54 GB/s | 3.6M shed (saturated) |
| docker 1cpu | `--conns 5000 --threads 8 --group 100 --rate 2 --duration 15 --size 256` | **989,294/s** | 298 MB/s | 0 |
| docker 1cpu | same, `--rate 5` | 295,201/s | 89 MB/s | 376k shed (saturated) |

With the Python client the same native fan-out measured only 1.85M/s — the C++
client revealed **4.2× more headroom**.

Other native stress shapes (Python client): 10 KB payloads → 2.28 GB/s, 0 drops;
unthrottled flood → 712k msgs/s ingest absorbed; 40,000 connections established
in 2.5 s, 617 drops.

## Persistence

Command: `run_persistence_loadtest.sh` — 20k conns, group 10, rate 5, 15 s, 1 KB,
`--room-prefix pub-cache-grp-` (cache rooms trigger LMDB + MySQL per message).

| Stage | Deliveries (15 s) | Note |
|---|---|---|
| plain rooms | 9.44M | baseline |
| + LMDB | 11.08M | LMDB is free (≥ baseline) |
| + MySQL, inserts on event loop | 2.74M | **~4× collapse**, 27 s connect ramp |
| + MySQL, dedicated writer thread | recovered | see below |

**Writer-thread fix, docker 1cpu (5k conns, cache rooms, MySQL on):**

| | inserts on loop | writer thread |
|---|---|---|
| Deliveries/s | 128,697 | **224,981** (= no-persistence baseline) |
| Dropped messages | 252,572 | **0** |
| Dropped DB rows | — | 0 (375 batches persisted) |

Native accounting closed exactly: 1,327,328 rows enqueued = 273,854 inserted
(confirmed by `SELECT COUNT(*)`) + 1,053,474 shed by the bounded queue.
A single local MySQL connection absorbs ~18k rows/s.

## Webhooks

`run_webhook_loadtest.sh` — 2k conns, rate 2, 15 s, 256 B, all events enabled.

| Check | Result |
|---|---|
| Verification via bounded pool | 20/20 approved, off the event loop |
| Fire-and-forget delivery | mock counted 64,505 · server counted 64,505 · 0 failed · 0 dropped |
| Keep-alive drain correctness | proven by that exact match (also 363,256 and 610,674 in full-stack runs) |
| Deny path (endpoint down) | 403 |
| Message drops during webhook load | 0 |

Sustained dispatcher throughput ≈ 10–15k webhooks/s (single connection).

## Full stack (everything on, 20k conns, 1 KB, cache rooms, ~100k msgs/s offered)

| | native | docker 1cpu |
|---|---|---|
| Messages processed | 1.14M of 1.48M | 696k of 1.39M |
| LMDB writes ≡ MySQL rows | 1,137,149 ≡ ~1.147M | 695,819 ≡ ~696k |
| Webhooks (mock ≡ server) | 363,256 ≡ 363,256 | 610,674 ≡ 610,674 |
| Shed (webhooks / deliveries) | 818k / 425k | 126k / 1.31M |
| Outcome | clean shutdown | 95% CPU, ~570 MiB, `OOMKilled=false` |

## Functional suite (`run_test.sh`)

Echo ✓ · JSON-escaping round-trip ✓ · latency avg 0.261 ms, p50 0.166, p95 0.284,
p99 0.538 · fan-out 60,000 / 60,000 deliveries.

## Limits of one 1 CPU / 1 GB container

Measured by ramping connections until the container died
(`tests/run_limits_docker.sh`, then client containers on `slnet`):

| Connections | Peak memory | Outcome |
|---|---|---|
| 20,000 | 218 MiB | fine, lossless |
| 28,000 | 335 MiB | fine |
| **40,000** | **592 MiB** | **survives** — 40k connected in 3.7 s, 707,920 deliveries/s @ 215 MB/s, 98.3% delivered, 98% CPU |
| 50,000 | 1024 MiB | **OOM-killed** |
| 60,000 | 875 MiB | OOM-killed |
| 100,000 | 1022 MiB | OOM-killed (server did hit its 100k cap and reject, but died first) |

**Ceiling ≈ 45k connections per GB** (~12–15 KB per connection including kernel
socket buffers; ramp bursts cost more than steady state — 40k peaked at 592 MiB
while ramping and settled to 216 MiB).

> **This is now handled automatically** — see *OOM protection* below. The server
> clamps its own `connections` cap to what the detected memory limit can hold
> (~21k per GB for actively streaming connections) and pauses admission under
> memory pressure. The numbers above were measured *before* that protection and
> show the failure mode it prevents.

## OOM protection

The OOM was not simply "too many connections": the runaway term was **kernel
socket buffer memory** (`sock` in `memory.stat`), which grew 55 → 293 → 604 MiB
as a single CPU fell behind on draining fan-out.

**Root cause (a real defect):** backpressure was measured at the wrong layer.
`maxBackpressureInBytes` / `ws->getBufferedAmount()` only see uWS's *userspace*
queue, while Linux autotunes the *kernel* send buffer in front of it into the
megabytes. A slow consumer therefore looked healthy (4 KB limit never tripped)
while memory piled up invisibly until the cgroup OOM-killed the process — taking
every established connection with it.

Three defences, in order of importance:

1. **Bounded socket buffers** — `SO_SNDBUF`/`SO_RCVBUF` are set to 8 KB
   (`SL_SOCKET_SNDBUF`) on every accepted socket. Writes then hit `EAGAIN`
   quickly and uWS buffers in userspace, where the existing backpressure limit
   and `.dropped` path actually engage.
2. **Self-clamping connection cap** — at startup the server reads its cgroup
   memory limit and clamps `connections` to `(limit − 192 MiB) / 40 KB`
   (≈21k per GB). 40 KB is the measured cost of an *active* connection: ~8 KB
   app/anon plus ~32 KB of kernel buffers. Override with `SL_BYTES_PER_CONN`.
3. **Adaptive cap** — every 500 ms the guard measures
   `(working_set − baseline) / connections` and re-sizes the cap to fit the
   budget at the *current* traffic mix, so the fixed 40 KB estimate is only a
   starting point. Reported as `connection_limit` and
   `measured_bytes_per_connection` in `/metrics`.

   The response is deliberately **asymmetric**, and this is the important part:

   - **Shrinking is immediate.** Cost rising is a safety signal.
   - **Growing needs a full minute** of sustained evidence: working set below
     50% of the budget, the cap actually being the binding constraint, then at
     most +20% per step — and the cap is sized from the *peak* per-connection
     cost seen recently, not the latest sample.

   Why so cautious: a connection's memory cost is unknowable until it carries
   traffic. During a ramp, connections that have not yet sent anything measure
   ~12 KiB and look cheap; the same connections cost ~23 KiB once fan-out
   starts. An earlier, faster growth policy (3 samples ≈ 1.5 s) was measured
   doing exactly the wrong thing: it grew the cap to 44,162 on ramp-time
   optimism, traffic then started, and the container was OOM-killed — because
   admission control can refuse a *new* connection but can never take back one
   already admitted. Growth is an optimisation; over-admission is fatal.

4. **Memory watchdog** — samples the cgroup working set (usage minus reclaimable
   file cache — *not* process RSS, which excludes the kernel socket memory that
   actually kills you) every 100 ms and pauses new connections above 80% of the
   limit, resuming below 70%. Rejects with `503 SERVER_UNDER_MEMORY_PRESSURE`;
   established connections keep running. Exposed as `admission_paused` and
   `rejected_memory_pressure` in `/metrics`.

Validated at both workload extremes on 1 GB, 100k connections attempted:

| Workload | Cap behaviour | Peak memory | Result |
|---|---|---|---|
| Heavy (512 B, rate 2) | held at 21,299 | 485 MiB | survives |
| Light (16 B, rate 0.5) | held at 21,299 | 256 MiB | survives |

The light case does not grow within a 45-second test *by design* — a minute of
proven quiet is the price of admission for a bigger cap. A long-running light
workload grows in +20% steps; an operator who knows their traffic can still set
the starting point directly with `SL_BYTES_PER_CONN`.

Verified: the load that previously OOM-killed the container (100k connection
attempts, 512-byte fan-out, two client containers) now peaks at 448 MiB with
`sock` bounded at 181 MiB, delivers 32M messages and survives — without the
watchdog even needing to fire. The watchdog was separately verified in isolation
(with the clamp neutralised via `SL_BYTES_PER_CONN=1000`): it paused at 878 MiB,
rejected 24,715 connections, recovered at 744 MiB, no OOM.

Recommended run (the sysctls cap per-socket autotuning; `net.ipv4.tcp_mem` is
*not* namespaced and Docker will refuse it):

```
docker run -d --name sl-server --cpus=1 --memory=1g \
  --ulimit nofile=1048576:1048576 \
  --sysctl net.ipv4.tcp_wmem="4096 8192 65536" \
  --sysctl net.ipv4.tcp_rmem="4096 8192 65536" \
  --network slnet -p 8080:8080 -e SL_THREADS=1 sl-server
```

Plaintext connections cost far less than the old TLS build's ~50 KB each, but
more than the earlier ~11 KB estimate once kernel socket memory (charged to the
container cgroup) is counted.

### Driving >28k connections

A single client cannot exceed **~28,232 connections** to one destination — that
is the default ephemeral port range (32768–60999), and source-IP rotation does
*not* survive the Docker published-port path. Two ways past it:

- one client container with a widened range:
  `--sysctl net.ipv4.ip_local_port_range="1024 65535"` (~64k ports) — used for
  the 40k verification above;
- several client containers on `slnet` (each has its own IP, hence its own full
  range) — give each a distinct `--uid-prefix`, since duplicate uids are rejected.

Client containers connect to `sl-server:8080` by name (loadgen resolves hostnames).

## Caveats

1. **Client co-located and, for Python runs, GIL-bound.** Every Python-client
   number is a floor; `loadgen` raised the same measurement 4.2×. True ceilings
   need the client on separate hardware.
2. **Never run a native server while the container publishes 8080.** WSL mirrored
   networking lets both bind silently and *splits traffic* between them — this
   invalidated one run (symptoms: ~27 s connect ramps, metrics from the wrong
   process). Check `ss -tln | grep 8080` shows no listener before starting.
3. **`loadgen --flood` starves its own reads** (send loop dominates), so it
   measures ingress only; use `--rate` for delivery figures.
4. **Windowed rates skew on slow ramps** (client still connecting when the window
   opens). Prefer the cumulative counters when a run reports a long `setup_s`.
5. `loadtest.py` reuses uids across runs, so back-to-back runs can see 409s from
   connections that have not yet closed.
6. **Samplers must print wall timestamps.** Spinning a curl container per sample
   costs 2–5 s each, so a loop's nominal `t=12s` label can be 30 s of wall time —
   this manufactured a "mid-run mass disconnect" that was really the load
   generator's own teardown at window end (postmortem below). Use `docker exec`
   for sub-second samples and stamp every line with `date +%s`.
7. **`connections` in `/metrics` is the app's counter.** When it disagrees with
   reality, `ls /proc/1/fd | wc -l` inside the container is the kernel's answer.

---

# Hardening round 2 (Sep–Oct 2026)

Everything below ran against the containerized server (1 CPU / 1 GB unless
noted) with the C++ `loadgen`. Reproduce with `tests/sweep_matrix.sh` (+
`tests/sweep_report.py`) and `tests/stress_suite.sh`.

## Structured sweep (17 runs: room size × payload × rate × persistence × webhooks)

OFAT from a baseline of 5 000 conns, rooms of 10, 1 KB, rate 5/conn. Key results:

| dimension | finding |
|---|---|
| room size | delivery = `msg_rate × (group−1)`; rooms of 100 at rate 5 already saturate one core (delivers 137 k/s, drops 79 k/s) |
| payload | 100 B and 1 KB deliver the **same** ~225 k msgs/s (cost = the send syscall); ~9.5 KB flips to bandwidth-bound at ~522 MB/s |
| rate | lossless to ~225 k del/s on one core; past it, delivery plateaus ~144 k/s with backpressure drops (lossy, never fatal) |
| persistence | LMDB write on the delivery path costs ~45 % (225 k → 123 k); MySQL adds little more (→ 102 k, dedicated writer thread) |
| webhooks | barely dent delivery (225 k → 220 k, fire-and-forget); dispatcher caps ~11 k hooks/s and the byte-bounded queue sheds the excess |

Two pitfalls encoded in the harness: the server must be **recreated per run**
(a single 1-CPU server degrades across back-to-back 5 k-conn runs — later runs
saw ~2.9 k connect failures from cumulative socket churn), and large-payload
runs use **9 500-byte bodies** because `maxPayloadLength` (10 240) bounds the
whole frame — a 10 240-byte body plus the JSON envelope is correctly rejected.

## Segfault found and fixed: shedding inside TopicTree::drain

The all-on 9.5 KB flood crashed the server (exit 139, not OOM) the moment
memory-pressure shedding engaged. gdb (in-container, `--cap-add=SYS_PTRACE`)
pinned it to `uWS::TopicTree::drain()` walking `s = s->next`: the `.dropped`
handler ran `ws->end()` synchronously, freeing the very `Subscriber` the walk
was on — a use-after-free. Fixed (`9cb898d`) by deferring the close past the
drain via `runOnOwnerThread` (re-validates by uid, never dangles) with a
`shedScheduled` guard. 6/6 post-fix floods survived with shedding fully active
(4.1–4.4 k closes/run) where every pre-fix run crashed.

## Vacate-delete batching (A/B)

Emptying a cache room used to commit (and `msync`, under `MDB_WRITEMAP`) one
LMDB transaction per room, on the event loop. 2 500 cache rooms vacating at
once: loop drained to 0 connections in **~41 s before, ~5 s after** moving the
range-deletes into the next batched flush (`2053b78`; sequence cut-off keeps
messages published after a refill).

## What a 1 GB all-on box's memory is (cgroup memory.stat, 4 000 conns, overload)

anon **343 MiB** + LMDB page cache **393 MiB** (entirely clean, `file_dirty=0`)
+ kernel socket buffers **134 MiB** ≈ 900 MiB charge. The guard's working-set
(charge − inactive_file) correctly excludes the reclaimable LMDB cache, and the
adaptive cap's climb (43 → 130 KiB/conn) is genuine overload cost — buffers, not
misattributed file pages.

## Load-generator teardown artifact (fixed)

After flood runs the server took ~120 s to reach 0 connections. Cause: client.
Under flood each socket's send queue is full, so plain `close()` queued the FIN
behind unsent data and the container's netns died before it was sent — the
server held dead peers until `idleTimeout` (120 s) reaped them, exactly as
designed for a vanished client. `loadgen` now closes with `SO_LINGER{on,0}`
(immediate RST): measured flood drain **121 s → 1 s** on identical server code.
This mattered beyond cosmetics — in multi-phase suites the zombie sockets of one
phase contaminated the next (inflated memory, depressed throughput).

## Stress suite, clean run (tests/stress_suite.sh, post-fixes)

| phase | result |
|---|---|
| A all-on 9.5 KB flood, 768 MB, 30 s | survives; guard paused/recovered **4×**, shed 13, drain 1 s, peak 656 MiB, 0 errors |
| B 5× churn, 1 500 cache-room vacates/cycle | drains 0–1 s, memory flat 21–25 MiB across cycles, 0 drops |
| C 2 workers, 400 state rooms, flood | **316 717 deliveries/s**, drain 1 s (earlier 118 k/s figure was zombie-socket-depressed) |
| D plain-flood + cache-r20 + state-r10 concurrently, all-on | all connect, drain 1 s, webhook queue sheds 124 k, 0 errors |
| E 60 s all-on soak, 4 000 conns | **88 drops total**, zero pressure events, peak 293 MiB, +72 MiB first→last quarter (LMDB history filling; releases after) |

## Postmortem: the mass-disconnect that wasn't

A soak appeared to show every connection closing mid-run with nothing in the
counters to explain it. After exonerating MySQL, webhooks, LMDB, conntrack
(max 262 k, peak 4.6 k), kernel TCP aborts (all zero) and the client (new
close-cause counters: zero closes on its side), the server's own log settled
it: the adaptive cap read **4 000 connections four seconds before** the "mass
close", every close line stamped the same second, and plain rooms delivered
99.7 % over the full window at a sustained 40 k msgs/s in. The burst was the
loadgen's deliberate RST teardown at window end; the "mid-run" appearance came
from unstamped samplers drifting 2–5 s per sample (caveat 6). No server bug.
Kept from the hunt: `.close` now logs the WS close code + reason at DEBUG, and
`loadgen` reports why it closed each socket (`close_eof/errhup/recverr/senderr`).
