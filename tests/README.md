# Local test harness

Scripts for running `SocketlinkClientServer` on a dev machine and comparing this
branch against `master`. The server is normally built for a provisioned droplet
(it fetches config from the metadata service + master server, waits for DNS, and
provisions a certbot cert on port 443), so it can't run locally as-is.

Compiling with **`-DLOCAL_TEST`** bypasses all of that: `main()` hardcodes a
minimal config, TLS uses the repo's `../ssl/` certs, and the server listens on
**port 9001**. This is guarded entirely by `#ifdef`, so production builds are
unaffected. Setting **`SL_TEST_WEBHOOK=1`** in the environment additionally
enables an `ON_MESSAGE` webhook pointing at `127.0.0.1:8443` (the mock below).

## Prerequisites (Linux / WSL)

apt dev libs:

```bash
sudo apt-get install -y build-essential git curl \
  libssl-dev zlib1g-dev liblmdb-dev libtbb-dev libboost-all-dev \
  libmysqlclient-dev libbpf-dev
```

Header-only + uWebSockets deps, staged under `$SL_DEPS` (default `~/sl-deps`):

- `include/httplib.h` (cpp-httplib), `include/json.hpp` (nlohmann), `include/simdjson.h` + `simdjson.cpp` (simdjson amalgamation)
- `uWebSockets/` cloned with submodules; build uSockets with `cd uWebSockets/uSockets && WITH_OPENSSL=1 make`

## Build both binaries

```bash
tests/build_local.sh          # -> ~/sl-bin/sl_new (this branch), ~/sl-bin/sl_orig (master)
```

(`OUT_DIR` overrides the output dir; default `~/sl-bin`, which is persistent —
`/tmp` is tmpfs and is wiped when the WSL VM restarts.)

## Run the tests

Functional parity + latency + throughput (no webhooks):

```bash
tests/run_test.sh ~/sl-bin/sl_new new
tests/run_test.sh ~/sl-bin/sl_orig orig
```

Async-webhook demonstration (mock endpoint stalls the TLS handshake ~1s):

```bash
tests/run_webhook_demo.sh ~/sl-bin/sl_orig orig   # synchronous: delivery stalls ~1000 ms
tests/run_webhook_demo.sh ~/sl-bin/sl_new  new    # async dispatch: delivery stays ~50 ms
```

## Load test (many connections, fan-out throughput)

`loadtest.py` opens N WebSocket connections across worker processes, subscribes
each into a fan-out room of `--group`, then every connection sends at `--rate`
msgs/sec for `--duration`. It scales past the ~28k ephemeral-port limit by
binding client sockets across loopback source IPs (`--src-ips`).

```bash
tests/run_loadtest.sh ~/sl-bin/sl_new --conns 30000 --procs 16 --group 10 --rate 5 --duration 10
```

Reports connections established, client send/recv throughput, and the server's
own `/api/v1/metrics` delta. `connections_reported_start` is the server-side
confirmation of concurrent connections. Note `messages_sent` is *local-only*
(the server's `numSubscribers` counts only same-worker subscribers), so
`client.recv` is the truer fan-out delivery count.

Observed on a 20-core / 15 GB WSL2 VM running **both** server and client:
stable to ~45k connections (45k conns, ~3.2M deliveries/s, 0 drops); ~55k stalls
during connection setup and ~60k destabilizes the VM (OOM). Reaching 100k needs
client and server on separate hosts (or a larger box) — this is a host limit,
not a server limit.

## Backpressure / stability test

Proves the server survives extreme backpressure without crashing: `N_SLOW`
subscribers join a room and then never read (their send buffers back up past
`maxBackpressure`), while a publisher floods that room; a separate healthy
pub/sub pair must keep exchanging the whole time.

```bash
tests/run_backpressure.sh ~/sl-bin/sl_new
```

Reports whether the server stayed **alive**, its **peak RSS** (must stay bounded —
it drops, not buffers-forever), the **healthy-client responsiveness %**, and the
**dropped_messages** count. This is the regression guard for a real crash that was
found and fixed: the `.dropped` handler used to `ws->send()` a notification, but on
an already-full buffer that send was itself dropped and re-invoked `.dropped`,
recursing until the stack overflowed (SIGSEGV). Post-fix result under a hard flood:
server alive, healthy client 100% responsive, RSS ~360 MB, ~7M messages dropped
cleanly.

## Files

| File | Purpose |
|---|---|
| `wsclient.py` | Pure-stdlib WebSocket+TLS client; functional/latency/throughput tests |
| `webhook_demo.py` | Measures message-delivery latency while webhooks fire |
| `mock_webhook.py` | Mock HTTPS webhook that stalls the TLS handshake (`DELAY` arg, default 1s) |
| `run_test.sh` | Boot server → run `wsclient.py` → tear down |
| `run_webhook_demo.sh` | Boot mock + server (`SL_TEST_WEBHOOK=1`) → run `webhook_demo.py` |
| `build_local.sh` | Build `/tmp/sl_new` and `/tmp/sl_orig` in `LOCAL_TEST` mode |
| `patch_orig.py` | Applies the `LOCAL_TEST` bypass to a `master` copy for the baseline build |
| `run_backpressure.sh` | Floods the server via non-reading subscribers; checks it survives + stays bounded |
| `backpressure_test.py` | Slow-subscriber flood + healthy-client responsiveness check |

Notes:
- `RUN_DIR` (default `~/sl-run`) is the server's working dir; keep it on a native
  Linux fs — LMDB uses `MDB_WRITEMAP`, which misbehaves on `/mnt/c` (drvfs).
- This uWS build does **not** echo a publish back to the publishing socket, so
  tests use a separate publisher and subscriber.
- `SL_DEPS` overrides the dependency location (default `~/sl-deps`).
