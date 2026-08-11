#include "MemoryGuard.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "Config.h"
#include "Logging.h"

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

    /** Target steady-state utilisation for the adaptive cap. Below the 80% pause
     *  watermark so the cap does the work and the watchdog stays a backstop. */
    constexpr double kAdaptiveTarget = 0.70;
    /** Don't trust a measurement taken from a handful of connections. */
    constexpr int kMinSampleConns = 500;
    /** Never believe a per-connection cost below this (guards against a cap so
     *  large that a traffic change cannot be absorbed). */
    constexpr unsigned long long kMinBytesPerConn = 12ULL * 1024;
    /** Growth is capped per step: the cost of being wrong in the "too many
     *  connections" direction is death, the cost of being wrong the other way is
     *  a few refused connections. Shrink immediately, grow 20% at a time. */
    constexpr double kMaxGrowthPerStep = 1.20;
    /**
     * Consecutive agreeing samples required before growing (at 500ms each, this
     * is a full minute of sustained headroom).
     *
     * Deliberately slow. A connection's memory cost is not knowable until it
     * carries traffic: during a ramp, connections that have not yet sent
     * anything measure ~12 KiB and look cheap, but the same connections cost
     * ~23 KiB once fan-out starts. Growing on a few seconds of that optimism
     * admitted 44k connections that then became too expensive — and admission
     * control cannot take a connection back, so the container was OOM-killed.
     * Requiring a minute of quiet means only a genuinely steady, genuinely light
     * workload earns a larger cap; a ramp never does.
     */
    constexpr int kGrowthConfirmations = 120;
    /** The remembered worst-case per-connection cost decays this much per step
     *  once the workload genuinely lightens (≈35 steps, ~70s, to halve). */
    constexpr double kPeakDecayPerStep = 0.98;

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

    unsigned long long readFirstNumber(const char* path) {
        FILE* f = std::fopen(path, "r");
        if (!f) {
            return 0;
        }
        char buf[128] = {0};
        unsigned long long v = 0;
        if (std::fgets(buf, sizeof(buf), f)) {
            if (std::strncmp(buf, "max", 3) == 0) { /** cgroup v2: uncapped */
                v = 0;
            } else {
                v = std::strtoull(buf, nullptr, 10);
            }
        }
        std::fclose(f);
        return v;
    }

    /** value of a "Key: <n> kB" line in a /proc file, in bytes */
    unsigned long long readProcKb(const char* path, const char* key) {
        FILE* f = std::fopen(path, "r");
        if (!f) {
            return 0;
        }
        char line[256];
        size_t keyLen = std::strlen(key);
        unsigned long long out = 0;
        while (std::fgets(line, sizeof(line), f)) {
            if (std::strncmp(line, key, keyLen) == 0) {
                out = std::strtoull(line + keyLen, nullptr, 10) * 1024ULL;
                break;
            }
        }
        std::fclose(f);
        return out;
    }

} // namespace

unsigned long long memoryLimitBytes() {
    static unsigned long long cached = []() -> unsigned long long {
        /** cgroup v2 (docker --memory maps here), then v1, then host RAM */
        unsigned long long v = readFirstNumber("/sys/fs/cgroup/memory.max");
        if (v == 0) {
            v = readFirstNumber("/sys/fs/cgroup/memory/memory.limit_in_bytes");
            /** v1 reports a sentinel ~2^63 when uncapped */
            if (v >= (1ULL << 62)) {
                v = 0;
            }
        }
        if (v == 0) {
            v = readProcKb("/proc/meminfo", "MemTotal:");
        }
        return v;
    }();
    return cached;
}

namespace {
    /** value of a "<key> <n>" line in a cgroup memory.stat-style file, in bytes */
    unsigned long long readCgroupStat(const char* path, const char* key) {
        FILE* f = std::fopen(path, "r");
        if (!f) {
            return 0;
        }
        char line[256];
        size_t keyLen = std::strlen(key);
        unsigned long long out = 0;
        while (std::fgets(line, sizeof(line), f)) {
            if (std::strncmp(line, key, keyLen) == 0 && line[keyLen] == ' ') {
                out = std::strtoull(line + keyLen + 1, nullptr, 10);
                break;
            }
        }
        std::fclose(f);
        return out;
    }
} // namespace

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
    unsigned long long usage = readFirstNumber("/sys/fs/cgroup/memory.current");
    if (usage > 0) {
        unsigned long long inactiveFile = readCgroupStat("/sys/fs/cgroup/memory.stat", "inactive_file");
        return (usage > inactiveFile) ? (usage - inactiveFile) : usage;
    }

    /** cgroup v1 */
    usage = readFirstNumber("/sys/fs/cgroup/memory/memory.usage_in_bytes");
    if (usage > 0) {
        unsigned long long inactiveFile = readCgroupStat("/sys/fs/cgroup/memory/memory.stat", "total_inactive_file");
        return (usage > inactiveFile) ? (usage - inactiveFile) : usage;
    }

    /** not containerized: fall back to this process's RSS */
    unsigned long long v = readProcKb("/proc/self/status", "RssAnon:");
    if (v == 0) {
        v = readProcKb("/proc/self/status", "VmRSS:");
    }
    return v;
}

int safeConnectionCap(unsigned long long limitBytes) {
    if (limitBytes == 0) {
        return 0; /** unknown: caller keeps the configured value */
    }
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
    if (limitBytes <= kBaseReserveBytes) {
        return 1000; /** tiny box: allow something, the watchdog governs */
    }
    unsigned long long usable = limitBytes - kBaseReserveBytes;
    unsigned long long cap = usable / perConn;
    if (cap > 2000000ULL) {
        cap = 2000000ULL;
    }
    return static_cast<int>(cap);
}

bool admissionPaused() { return g_paused.load(std::memory_order_relaxed); }

unsigned long long memoryRejectionCount() { return g_rejections.load(std::memory_order_relaxed); }

void countMemoryRejection() { g_rejections.fetch_add(1, std::memory_order_relaxed); }

unsigned long long connectionShedCount() { return g_shed.load(std::memory_order_relaxed); }

void countConnectionShed() { g_shed.fetch_add(1, std::memory_order_relaxed); }

void enableAdaptiveCap(std::atomic<int>* connCounter, int hardMax) {
    g_connCounter = connCounter;
    g_hardMax.store(hardMax, std::memory_order_relaxed);
}

unsigned long long measuredBytesPerConnection() { return g_bytesPerConn.load(std::memory_order_relaxed); }

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
        int conns = counter->load(std::memory_order_relaxed);
        if (conns < kMinSampleConns) {
            return;
        }

        unsigned long long baseline = g_baselineBytes.load(std::memory_order_relaxed);
        if (workingSet <= baseline) {
            return;
        }

        unsigned long long perConn = (workingSet - baseline) / (unsigned long long)conns;
        if (perConn < kMinBytesPerConn) {
            perConn = kMinBytesPerConn;
        }
        g_bytesPerConn.store(perConn, std::memory_order_relaxed);

        /** Size from the PEAK cost, not the latest sample. A connection that was
         *  once expensive can become expensive again the moment traffic returns,
         *  and by then it is too late to reclaim the memory. The peak decays
         *  slowly so a genuinely lighter workload does eventually earn a bigger
         *  cap — over a minute, not instantly. */
        if ((double)perConn > g_peakBytesPerConn) {
            g_peakBytesPerConn = (double)perConn;
        } else {
            g_peakBytesPerConn *= kPeakDecayPerStep;
            if (g_peakBytesPerConn < (double)perConn) {
                g_peakBytesPerConn = (double)perConn;
            }
        }

        unsigned long long target = (unsigned long long)(limit * kAdaptiveTarget);
        if (target <= baseline) {
            return;
        }
        long long newCap = (long long)((target - baseline) / (unsigned long long)g_peakBytesPerConn);

        int hardMax = g_hardMax.load(std::memory_order_relaxed);
        int current = UserData::getInstance().connections;

        /** Asymmetric response: shrinking is a safety action and takes effect at
         *  once; growing is an optimisation and must earn its way — several
         *  agreeing samples, then at most +20% per step. */
        if (newCap > current) {
            /**
             * Only grow with proven headroom. A measurement taken mid-ramp is
             * optimistic — connections that have not finished subscribing, and
             * have not yet carried traffic, look cheap — and raising the cap on
             * that optimism lets the rush fill the new headroom before the true
             * cost is known (observed: an early 12 KiB/conn sample raised the cap
             * to 59k, which filled before the cost resolved to 23 KiB/conn).
             * Requiring usage below half the budget means growth only happens
             * from a genuinely quiet state.
             */
            if (workingSet > (unsigned long long)(limit * 0.5)) {
                g_growthStreak = 0;
                return;
            }
            /** and only if the cap is actually the binding constraint — no point
             *  raising a ceiling nobody is reaching */
            if ((long long)conns * 10 < (long long)current * 9) {
                g_growthStreak = 0;
                return;
            }
            if (++g_growthStreak < kGrowthConfirmations) {
                return;
            }
            g_growthStreak = 0;
            long long maxGrown = (long long)(current * kMaxGrowthPerStep);
            if (newCap > maxGrown) {
                newCap = maxGrown;
            }
        } else {
            g_growthStreak = 0;
        }

        if (newCap > hardMax) {
            newCap = hardMax;
        }
        if (newCap < 1000) {
            newCap = 1000;
        }

        /** ignore small wobbles: only move on a >10% change */
        long long delta = newCap - current;
        if (delta < 0) {
            delta = -delta;
        }
        if (delta * 10 < current) {
            return;
        }

        log(LogLevel::INFO, "Adaptive cap: ", current, " -> ", newCap, " (measured ", perConn / 1024,
            " KiB/conn at ", conns, " connections, ", workingSet / (1024 * 1024), " MiB used)");
        setConnectionLimit((int)newCap);
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
