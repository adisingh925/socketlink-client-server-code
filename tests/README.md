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
tests/build_local.sh          # -> /tmp/sl_new (this branch), /tmp/sl_orig (master)
```

## Run the tests

Functional parity + latency + throughput (no webhooks):

```bash
tests/run_test.sh /tmp/sl_new new
tests/run_test.sh /tmp/sl_orig orig
```

Async-webhook demonstration (mock endpoint stalls the TLS handshake ~1s):

```bash
tests/run_webhook_demo.sh /tmp/sl_orig orig   # synchronous: delivery stalls ~1000 ms
tests/run_webhook_demo.sh /tmp/sl_new  new    # async dispatch: delivery stays ~50 ms
```

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

Notes:
- `RUN_DIR` (default `~/sl-run`) is the server's working dir; keep it on a native
  Linux fs — LMDB uses `MDB_WRITEMAP`, which misbehaves on `/mnt/c` (drvfs).
- This uWS build does **not** echo a publish back to the publishing socket, so
  tests use a separate publisher and subscriber.
- `SL_DEPS` overrides the dependency location (default `~/sl-deps`).
