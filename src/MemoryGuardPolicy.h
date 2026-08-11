#pragma once

/**
 * Pure, side-effect-free policy for the memory guard: the cap arithmetic and the
 * /proc + cgroup parsers, separated from the threading and global state in
 * MemoryGuard.cpp so every branch can be driven deterministically from a test
 * (see tests/memoryguard_test.cpp). Header-only and dependency-free on purpose —
 * the test compiles against this alone.
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

/* ---- adaptive-cap policy constants (shared with MemoryGuard.cpp) ---------- */

/** Target steady-state utilisation for the adaptive cap. Below the 80% pause
 *  watermark so the cap does the work and the watchdog stays a backstop. */
inline constexpr double kAdaptiveTarget = 0.70;
/** Don't trust a measurement taken from a handful of connections. */
inline constexpr int kMinSampleConns = 500;
/** Growth is capped per step: being wrong toward "too many connections" is
 *  death; the other way costs a few refused connections. Shrink now, grow +20%. */
inline constexpr double kMaxGrowthPerStep = 1.20;
/** Consecutive agreeing samples required before growing (120 * 500ms = 1 min of
 *  sustained headroom), so a ramp's optimistic early samples never earn growth. */
inline constexpr int kGrowthConfirmations = 120;
/** The remembered worst-case per-connection cost decays this much per step once
 *  the workload genuinely lightens (~35 steps, ~70s, to halve). */
inline constexpr double kPeakDecayPerStep = 0.98;

/* ---- pure /proc + cgroup parsers ------------------------------------------ */

/** First whitespace-delimited number in `path`; 0 if missing/unreadable. The
 *  cgroup-v2 sentinel "max" (uncapped) reads as 0. */
inline unsigned long long mgReadFirstNumber(const char* path) {
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

/** Value of a "Key: <n> kB" line in a /proc file, converted to bytes; 0 if the
 *  key is absent. */
inline unsigned long long mgReadProcKb(const char* path, const char* key) {
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

/** Value of a "<key> <n>" line in a cgroup memory.stat-style file, in bytes; 0
 *  if the key is absent. The trailing space guard stops "inactive_file" from
 *  matching a prefix like "inactive_file_foo". */
inline unsigned long long mgReadCgroupStat(const char* path, const char* key) {
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

/* ---- pure cap arithmetic -------------------------------------------------- */

/** How many connections of `perConn` bytes fit in `limitBytes` after holding
 *  back `baseReserve` for non-per-connection memory (binary, LMDB, queues).
 *  0 when the limit is unknown; 1000 on a box too small to reserve from; capped
 *  at 2,000,000. */
inline int
computeSafeConnectionCap(unsigned long long limitBytes, unsigned long long perConn, unsigned long long baseReserve) {
    if (limitBytes == 0) {
        return 0; /** unknown: caller keeps the configured value */
    }
    if (limitBytes <= baseReserve) {
        return 1000; /** tiny box: allow something, the watchdog governs */
    }
    unsigned long long usable = limitBytes - baseReserve;
    unsigned long long cap = usable / perConn;
    if (cap > 2000000ULL) {
        cap = 2000000ULL;
    }
    return static_cast<int>(cap);
}

/** Inputs for one adaptive-cap step (everything the decision reads, made
 *  explicit so the policy is a pure function of them). */
struct AdaptiveCapParams {
    unsigned long long limit;           /** memory budget */
    unsigned long long workingSet;      /** current working set (cgroup charge) */
    unsigned long long baseline;        /** memory in use before any connections */
    int conns;                          /** live connection count */
    int current;                        /** currently configured cap */
    int hardMax;                        /** operator ceiling, never exceeded */
    unsigned long long minBytesPerConn; /** floor on believed per-conn cost */
};

/** Carried between steps: the decayed worst-case cost and the growth streak. */
struct AdaptiveCapState {
    double peakBytesPerConn;
    int growthStreak;
};

struct AdaptiveCapDecision {
    bool changed; /** apply newCap via setConnectionLimit */
    int newCap;
    bool measured; /** measuredBytesPerConn is valid */
    unsigned long long measuredBytesPerConn;
};

/**
 * Decide the next connection cap from measured per-connection memory cost.
 *
 * Identical arithmetic to the guard's inline version, made pure: mutates only the
 * passed-in `state`, returns the decision, performs no I/O. Asymmetric by design
 * — shrink immediately (safety), grow only after kGrowthConfirmations agreeing
 * samples from a genuinely quiet state and then at most +kMaxGrowthPerStep.
 */
inline AdaptiveCapDecision computeAdaptiveCap(const AdaptiveCapParams& p, AdaptiveCapState& state) {
    AdaptiveCapDecision d{false, p.current, false, 0};

    if (p.conns < kMinSampleConns) {
        return d;
    }
    if (p.workingSet <= p.baseline) {
        return d;
    }

    unsigned long long perConn = (p.workingSet - p.baseline) / (unsigned long long)p.conns;
    if (perConn < p.minBytesPerConn) {
        perConn = p.minBytesPerConn;
    }
    d.measured = true;
    d.measuredBytesPerConn = perConn;

    /** Size from the PEAK cost, not the latest sample: a connection that was once
     *  expensive can become expensive again the instant traffic returns, and by
     *  then the memory cannot be reclaimed. The peak decays slowly so a genuinely
     *  lighter workload eventually earns a bigger cap. */
    if ((double)perConn > state.peakBytesPerConn) {
        state.peakBytesPerConn = (double)perConn;
    } else {
        state.peakBytesPerConn *= kPeakDecayPerStep;
        if (state.peakBytesPerConn < (double)perConn) {
            state.peakBytesPerConn = (double)perConn;
        }
    }

    unsigned long long target = (unsigned long long)(p.limit * kAdaptiveTarget);
    if (target <= p.baseline) {
        return d;
    }
    long long newCap = (long long)((target - p.baseline) / (unsigned long long)state.peakBytesPerConn);

    if (newCap > p.current) {
        /** Only grow with proven headroom: a mid-ramp measurement is optimistic
         *  (unsubscribed, trafficless connections look cheap). Require usage below
         *  half the budget so growth only happens from a genuinely quiet state. */
        if (p.workingSet > (unsigned long long)(p.limit * 0.5)) {
            state.growthStreak = 0;
            return d;
        }
        /** and only if the cap is actually the binding constraint */
        if ((long long)p.conns * 10 < (long long)p.current * 9) {
            state.growthStreak = 0;
            return d;
        }
        if (++state.growthStreak < kGrowthConfirmations) {
            return d;
        }
        state.growthStreak = 0;
        long long maxGrown = (long long)(p.current * kMaxGrowthPerStep);
        if (newCap > maxGrown) {
            newCap = maxGrown;
        }
    } else {
        state.growthStreak = 0;
    }

    if (newCap > p.hardMax) {
        newCap = p.hardMax;
    }
    if (newCap < 1000) {
        newCap = 1000;
    }

    /** ignore small wobbles: only move on a >10% change */
    long long delta = newCap - p.current;
    if (delta < 0) {
        delta = -delta;
    }
    if (delta * 10 < p.current) {
        return d;
    }

    d.changed = true;
    d.newCap = (int)newCap;
    return d;
}
