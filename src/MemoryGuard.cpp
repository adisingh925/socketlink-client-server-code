#include "MemoryGuard.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include "Logging.h"

namespace {

    std::atomic<bool> g_paused{false};
    std::atomic<unsigned long long> g_rejections{0};
    std::atomic<bool> g_started{false};

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

unsigned long long currentAnonRssBytes() {
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

    std::thread([limit]() {
        const unsigned long long high = (unsigned long long)(limit * kHighWatermark);
        const unsigned long long low = (unsigned long long)(limit * kLowWatermark);
        while (true) {
            unsigned long long rss = currentAnonRssBytes();
            bool paused = g_paused.load(std::memory_order_relaxed);

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
