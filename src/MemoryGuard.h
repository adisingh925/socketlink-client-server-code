#pragma once

/**
 * Memory-pressure guard.
 *
 * Load tests OOM-killed a 1 CPU / 1 GB container at 50k connections: the
 * `connections` hard cap (default 100,000) is a promise the memory budget cannot
 * keep, so the kernel killed the process (exit 137) LONG before the cap could
 * shed anything — the server logged "Connection limit reached" and died anyway.
 *
 * Two defences, both here:
 *   1. safeConnectionCap() — derives, from the cgroup/host memory limit, how many
 *      connections actually fit. main() clamps the configured cap to it at
 *      startup so the advertised limit is honest.
 *   2. startMemoryGuard() — a sampling thread that watches this process's
 *      anonymous RSS against the limit and flips admissionPaused() on at the high
 *      watermark and off at the low one (hysteresis). The WS upgrade handler
 *      rejects with 503 while paused, so the server sheds NEW connections and
 *      keeps serving established ones instead of being killed.
 *
 * Anonymous RSS (not cgroup memory.current) is the signal: page cache — notably
 * LMDB's MDB_WRITEMAP mapping — is reclaimable and would otherwise read as
 * permanent pressure.
 */
#include <atomic>
#include <cstdint>

/** Memory limit for this process: cgroup v2/v1 limit if capped, else host RAM.
 *  0 when it cannot be determined. Detected once, then cached. */
unsigned long long memoryLimitBytes();

/** Current memory working set as the OOM killer sees it: the cgroup's charge
 *  (which includes KERNEL socket buffers — the dominant cost at high connection
 *  counts) minus reclaimable file cache. Falls back to process RSS when not
 *  containerized. 0 if unavailable. */
unsigned long long currentMemoryWorkingSetBytes();

/** How many connections fit in `limitBytes`, after reserving a base allowance.
 *  Uses ~40 KB/connection (measured cost of an ACTIVE connection: ~8 KB app
 *  state plus ~32 KB of kernel socket buffers).
 *  SL_BYTES_PER_CONN overrides the per-connection estimate. */
int safeConnectionCap(unsigned long long limitBytes);

/** True while the server is shedding new connections due to memory pressure. */
bool admissionPaused();

/** Connections rejected because admission was paused. */
unsigned long long memoryRejectionCount();
void countMemoryRejection();

/** Established connections closed under memory pressure because they were
 *  backpressured (see the .dropped handler). Admission control alone cannot
 *  reclaim memory already committed to established connections; this can. */
unsigned long long connectionShedCount();
void countConnectionShed();

/** Start the sampling thread (idempotent; no-op if the limit is unknown). */
void startMemoryGuard();

/**
 * Enable the adaptive connection cap.
 *
 * A fixed bytes-per-connection estimate is always wrong for some workload: 40 KB
 * is right for heavy fan-out but ~3x too conservative for presence-style traffic,
 * while 8 KB (tried for small payloads) OOM-killed a 1 GB container at 71k
 * connections. So instead of guessing, measure: the guard periodically computes
 * (working_set - baseline) / connections and re-sizes the cap to whatever the
 * memory budget can actually hold AT THE CURRENT traffic mix.
 *
 * The cap only moves within [1000, hardMax]; hardMax is the operator's
 * configured `connections`, which is never exceeded. Lowering the cap never
 * disconnects anyone — it only refuses new connections until usage drops.
 *
 * `connCounter` is the live connection count (ServerState's globalConnectionCounter).
 */
void enableAdaptiveCap(std::atomic<int>* connCounter, int hardMax);

/** Bytes-per-connection currently measured (0 before the first sample). */
unsigned long long measuredBytesPerConnection();
