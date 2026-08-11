#include "MemoryGuard.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "Config.h"
#include "Logging.h"
#include "MemoryGuardPolicy.h"

namespace {

    std::atomic<bool> g_paused{false};
    std::atomic<unsigned long long> g_rejections{0};
    std::atomic<unsigned long long> g_shed{0};
    std::atomic<bool> g_started{false};

    /** adaptive cap state */
    std::atomic<int>* g_connCounter{nullptr};
    std::atomic<int> g_hardMax{0};
    std::atomic<unsigned long long> g_bytesPerConn{0};
    std::atomic<unsigned long long> g_baselineBytes{0};

    /* Adaptive-cap policy constants (kAdaptiveTarget, kMinSampleConns,
     * kMaxGrowthPerStep, kGrowthConfirmations, kPeakDecayPerStep) live in
     * MemoryGuardPolicy.h alongside the pure decision they drive. */

    /**
     * Never believe a per-connection cost below this.
     *
     * A genuinely idle connection measures ~5 KB, but idle is not a promise: the
     * moment those sockets start carrying fan-out they cost ~40 KB each, and a
     * cap sized on the idle figure would already have admitted far more than the
     * box can then hold — and admission control cannot take a connection back.
     * So the cap assumes at least this much even when it measures less, which is
     * what limits a 1 GB box to ~61k idle connections rather than the ~160k that
     * would physically fit.
     *
     * SL_MIN_BYTES_PER_CONN lowers it for a workload known to stay idle (and for
     * measuring the physical ceiling). Doing so trades the safety margin for
     * capacity: if that traffic assumption is wrong, the box OOMs.
     */
    unsigned long long minBytesPerConn() {
        static unsigned long long v = []() -> unsigned long long {
            if (const char* e = std::getenv("SL_MIN_BYTES_PER_CONN")) {
                unsigned long long n = std::strtoull(e, nullptr, 10);
                if (n > 0) {
                    return n;
                }
            }
            return 12ULL * 1024;
        }();
        return v;
    }
    /** worst per-connection cost seen recently — the cap is sized from this, not
     *  from the instantaneous sample, so a fan-out burst cannot be forgotten
     *  between measurements */
    double g_peakBytesPerConn = 0.0;
    int g_growthStreak = 0;

    /** Fraction of the limit at which new connections stop being admitted.
     *  Deliberately conservative: a fast ramp keeps allocating between samples,
     *  and measured overshoot after the trigger was ~100 MiB on a 1 GB budget
     *  (fired at 878 MiB, peaked at 982). 80% leaves room for that plus the
     *  buffers already-established connections may still grow. */
    constexpr double kHighWatermark = 0.80;
    /** and the fraction at which they resume (hysteresis, avoids flapping) */
    constexpr double kLowWatermark = 0.70;
    /** memory that is NOT per-connection: binary, LMDB dirty pages, batches,
     *  queues. Held back before dividing the rest among connections. */
    constexpr unsigned long long kBaseReserveBytes = 192ULL * 1024 * 1024;

} // namespace

unsigned long long memoryLimitBytes() {
    static unsigned long long cached = []() -> unsigned long long {
        /** cgroup v2 (docker --memory maps here), then v1, then host RAM */
        unsigned long long v = mgReadFirstNumber("/sys/fs/cgroup/memory.max");
        if (v == 0) {
            v = mgReadFirstNumber("/sys/fs/cgroup/memory/memory.limit_in_bytes");
            /** v1 reports a sentinel ~2^63 when uncapped */
            if (v >= (1ULL << 62)) {
                v = 0;
            }
        }
        if (v == 0) {
            v = mgReadProcKb("/proc/meminfo", "MemTotal:");
        }
        return v;
    }();
    return cached;
}

unsigned long long currentMemoryWorkingSetBytes() {
    /**
     * The number that matters is the one the OOM killer uses: the cgroup's
     * charge, NOT this process's anonymous RSS. With ~100k sockets most of the
     * footprint is KERNEL socket buffers — charged to the cgroup, invisible in
     * RssAnon. Measuring RssAnon let a 1 GB container reach its limit and get
     * killed while the guard still read ~90 MiB and never fired.
     *
     * Working set = cgroup usage minus inactive file cache (reclaimable), the
     * same definition Kubernetes uses for eviction decisions.
     */
    unsigned long long usage = mgReadFirstNumber("/sys/fs/cgroup/memory.current");
    if (usage > 0) {
        unsigned long long inactiveFile = mgReadCgroupStat("/sys/fs/cgroup/memory.stat", "inactive_file");
        return (usage > inactiveFile) ? (usage - inactiveFile) : usage;
    }

    /** cgroup v1 */
    usage = mgReadFirstNumber("/sys/fs/cgroup/memory/memory.usage_in_bytes");
    if (usage > 0) {
        unsigned long long inactiveFile = mgReadCgroupStat("/sys/fs/cgroup/memory/memory.stat", "total_inactive_file");
        return (usage > inactiveFile) ? (usage - inactiveFile) : usage;
    }

    /** not containerized: fall back to this process's RSS */
    unsigned long long v = mgReadProcKb("/proc/self/status", "RssAnon:");
    if (v == 0) {
        v = mgReadProcKb("/proc/self/status", "VmRSS:");
    }
    return v;
}

int safeConnectionCap(unsigned long long limitBytes) {
    /**
     * 40 KB per ACTIVE connection, not the ~12-15 KB an idle socket costs.
     *
     * Breakdown measured under 512-byte fan-out (cgroup memory.stat): ~8 KB of
     * anon/app state, plus KERNEL socket buffers — SL_SOCKET_SNDBUF (8 KB, which
     * the kernel doubles) for send AND receive, so ~32 KB. `sock` is the term
     * that runs away: it went 55 -> 293 -> 604 MiB as one CPU fell behind.
     *
     * Admission control cannot recover any of that — refusing NEW connections
     * does nothing about established ones — so the cap must be sized for the
     * admitted set while BUSY, not while idle. Sized at 15 KB a 1 GB container
     * admitted ~57k and was OOM-killed; at 24 KB, ~35k and still killed; at
     * 32 KB, ~27k and only just survived. The watchdog is a spike backstop, not
     * a substitute for honest sizing.
     */
    unsigned long long perConn = 40ULL * 1024;
    if (const char* e = std::getenv("SL_BYTES_PER_CONN")) {
        unsigned long long v = std::strtoull(e, nullptr, 10);
        if (v > 0) {
            perConn = v;
        }
    }
    return computeSafeConnectionCap(limitBytes, perConn, kBaseReserveBytes);
}

bool admissionPaused() {
    return g_paused.load(std::memory_order_relaxed);
}

unsigned long long memoryRejectionCount() {
    return g_rejections.load(std::memory_order_relaxed);
}

void countMemoryRejection() {
    g_rejections.fetch_add(1, std::memory_order_relaxed);
}

unsigned long long connectionShedCount() {
    return g_shed.load(std::memory_order_relaxed);
}

void countConnectionShed() {
    g_shed.fetch_add(1, std::memory_order_relaxed);
}

void enableAdaptiveCap(std::atomic<int>* connCounter, int hardMax) {
    g_connCounter = connCounter;
    g_hardMax.store(hardMax, std::memory_order_relaxed);
}

unsigned long long measuredBytesPerConnection() {
    return g_bytesPerConn.load(std::memory_order_relaxed);
}

namespace {
    /**
     * Re-size the connection cap from observed memory cost per connection.
     *
     * Called every couple of seconds from the guard thread. Uses the SAME budget
     * arithmetic as the startup clamp, but with a measured per-connection cost
     * instead of a compile-time guess, so a presence-style workload earns a much
     * larger cap than a heavy fan-out one — without either being able to OOM.
     */
    void adaptCap(unsigned long long limit, unsigned long long workingSet) {
        std::atomic<int>* counter = g_connCounter;
        if (!counter) {
            return;
        }

        AdaptiveCapParams p;
        p.limit = limit;
        p.workingSet = workingSet;
        p.baseline = g_baselineBytes.load(std::memory_order_relaxed);
        p.conns = counter->load(std::memory_order_relaxed);
        p.current = UserData::getInstance().connections;
        p.hardMax = g_hardMax.load(std::memory_order_relaxed);
        p.minBytesPerConn = minBytesPerConn();

        /** g_peakBytesPerConn and g_growthStreak are only ever touched here, on the
         *  single guard thread, so they need no synchronisation. computeAdaptiveCap
         *  reads and updates them through this local mirror. */
        AdaptiveCapState state{g_peakBytesPerConn, g_growthStreak};
        AdaptiveCapDecision d = computeAdaptiveCap(p, state);
        g_peakBytesPerConn = state.peakBytesPerConn;
        g_growthStreak = state.growthStreak;

        if (d.measured) {
            g_bytesPerConn.store(d.measuredBytesPerConn, std::memory_order_relaxed);
        }
        if (d.changed) {
            log(LogLevel::INFO, "Adaptive cap: ", p.current, " -> ", d.newCap, " (measured ",
                d.measuredBytesPerConn / 1024, " KiB/conn at ", p.conns, " connections, ", workingSet / (1024 * 1024),
                " MiB used)");
            setConnectionLimit(d.newCap);
        }
    }
} // namespace

void startMemoryGuard() {
    if (g_started.exchange(true)) {
        return;
    }
    unsigned long long limit = memoryLimitBytes();
    if (limit == 0) {
        log(LogLevel::WARN, "Memory guard disabled: could not determine a memory limit");
        return;
    }

    log(LogLevel::INFO, "Memory guard active: limit ", limit / (1024 * 1024), " MiB, pause at ",
        (unsigned long long)(kHighWatermark * 100), "%, resume at ", (unsigned long long)(kLowWatermark * 100), "%");

    /** memory in use before any connections exist — everything above this is
     *  attributable to connections, which is what the adaptive cap divides by */
    g_baselineBytes.store(currentMemoryWorkingSetBytes(), std::memory_order_relaxed);

    std::thread([limit]() {
        const unsigned long long high = (unsigned long long)(limit * kHighWatermark);
        const unsigned long long low = (unsigned long long)(limit * kLowWatermark);
        int tick = 0;
        while (true) {
            unsigned long long rss = currentMemoryWorkingSetBytes();
            bool paused = g_paused.load(std::memory_order_relaxed);

            /** Re-size the cap every ~500ms. Fast on purpose: a 1-core server
             *  admits thousands of connections per second, so a slow loop learns
             *  the true cost only after overshooting it. The measurement is two
             *  small /proc reads. */
            if (++tick >= 5) {
                tick = 0;
                adaptCap(limit, rss);
            }

            if (!paused && rss >= high) {
                g_paused.store(true, std::memory_order_relaxed);
                log(LogLevel::WARN, "MEMORY PRESSURE: ", rss / (1024 * 1024), " MiB of ", limit / (1024 * 1024),
                    " MiB — pausing new connections (existing ones keep running)");
            } else if (paused && rss <= low) {
                g_paused.store(false, std::memory_order_relaxed);
                log(LogLevel::INFO, "Memory recovered: ", rss / (1024 * 1024), " MiB — accepting connections again (",
                    memoryRejectionCount(), " rejected while paused)");
            }

            /** sample often enough to catch a fast connection ramp: 40k
             *  connections can arrive in under 4 seconds */
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }).detach();
}
