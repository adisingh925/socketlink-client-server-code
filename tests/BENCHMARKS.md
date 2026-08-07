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

> **Sizing rule:** the `connections` cap must be set from the memory budget.
> The compiled-in default of **100,000 is unsafe for a 1 GB container** — the
> process is OOM-killed long before the cap can shed load, so the hard limit
> never protects the deployment. Use ≈ **40,000 per GB** (leaving headroom for
> ramp bursts), i.e. `{"connections": 40000}` via `/api/v1/invalidate` for a
> 1 GB container.

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
