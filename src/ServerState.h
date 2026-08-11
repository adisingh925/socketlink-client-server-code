#pragma once

/**
 * Shared server state: socket/worker types, room registries (TBB concurrent
 * maps), global metrics counters, and the cross-thread execution helper.
 */
#include "App.h"

#include <tbb/concurrent_hash_map.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "MySQLHandler.h"

/**
 * Which worker threads hold at least one subscriber of a given room.
 *
 * Publishing used to defer to EVERY other worker unconditionally, so a message
 * to a 10-member room woke all 19 other loops on a 20-core box — a cross-thread
 * eventfd wakeup each, almost all of them finding nothing to send. That is the
 * measured cause of sub-linear scaling (1 CPU ~1M deliveries/s, 4 CPU 3M = 75%
 * efficient, 20 CPU 7.8M = only 39% efficient). With this mask a publish wakes
 * only the workers that can actually deliver.
 *
 * `counts` is per-worker subscriber refcounts (mutated only on the owning
 * worker's thread, so a relaxed fetch_add/sub pair is enough); `mask` is the
 * bitmask derived from it and is what the publish path reads.
 */
struct RoomWorkers {
    std::atomic<uint64_t> mask{0};
    std::vector<std::atomic<uint32_t>> counts;
    explicit RoomWorkers(size_t workerCount) : counts(workerCount) {}
};

/** One socket's membership of one room. */
struct RoomSub {
    uint8_t roomType = 255;
    /** Shared with every other subscriber of this room. Held by shared_ptr so the
     *  publish path needs NO map lookup and no lock: while this socket is
     *  subscribed its own worker bit is set, so the room entry cannot be erased
     *  underneath it. */
    std::shared_ptr<RoomWorkers> workers;
};

/* ws->getUserData returns one of these */
struct PerSocketData {
    std::string key;
    std::string uid;
    std::string metadata;

    /**
     * This socket's subscriptions (rid -> room type + worker mask). OWNER-THREAD
     * ONLY: every mutation site (openConnection/closeConnection) runs on the
     * socket's event loop (REST/ban callers get there via runOnOwnerThread), so
     * the per-message hot path reads this plain map with no locks or atomics at
     * all. The global ThreadSafe::uidToRoomMapping is maintained in the same code
     * paths and serves only cross-thread readers (REST validation, admin listings).
     */
    std::unordered_map<std::string, RoomSub> rooms;

    /**
     * true - sending allowed
     * false - sending not allowed
     */
    bool sendingAllowed = true;

    /** Set once this socket has been scheduled for memory-pressure shedding, so a
     *  storm of .dropped callbacks does not queue one deferred close per dropped
     *  message (see the .dropped handler in Worker.cpp). */
    bool shedScheduled = false;
};

/**
 * Plaintext HTTP/WS transport.
 *
 * The server speaks plain ws:// (no TLS). TLS is terminated upstream by a load
 * balancer / reverse proxy, so there is zero per-connection TLS handshake cost
 * in the app itself.
 */
using SLApp = uWS::App; // plaintext (non-TLS) uWebSockets app
using SLWebSocket = uWS::WebSocket<false, true, PerSocketData>;

/** uWebSocket worker runs in a separate thread */
struct worker_t {
    void work();

    /* uWebSocket worker listens on separate port, or share the same port (works on Linux). */
    struct us_listen_socket_t* listen_socket_;

    /* Every thread has its own Loop, and uWS::Loop::get() returns the Loop for current thread.*/
    struct uWS::Loop* loop_;

    /* Need to capture the uWS::App object (instance). */
    std::shared_ptr<SLApp> app_;

    /* Thread object for uWebSocket worker */
    std::shared_ptr<std::thread> thread_;
};

/** Rooms */
enum class Rooms : uint8_t {
    PUBLIC = 0,
    PRIVATE = 1,
    PUBLIC_STATE = 2,
    PRIVATE_STATE = 3,
    PUBLIC_CACHE = 4,
    PRIVATE_CACHE = 5,
    PUBLIC_STATE_CACHE = 6,
    PRIVATE_STATE_CACHE = 7
};

/**
 * Derive the room type from a room id's prefix. Returns 255 when the prefix is
 * not a recognized room type. Longer/more-specific prefixes are checked first.
 * (Previously this ladder was copy-pasted in the subscribe/unsubscribe/ban handlers.)
 */
inline uint8_t parseRoomType(const std::string& rid) {
    if (rid.rfind("pub-state-cache-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE);
    if (rid.rfind("pri-state-cache-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE);
    if (rid.rfind("pub-cache-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PUBLIC_CACHE);
    if (rid.rfind("pri-cache-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PRIVATE_CACHE);
    if (rid.rfind("pub-state-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PUBLIC_STATE);
    if (rid.rfind("pri-state-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PRIVATE_STATE);
    if (rid.rfind("pub-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PUBLIC);
    if (rid.rfind("pri-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PRIVATE);
    return 255;
}

/** stores data for websocket and its worker for later use */
struct WebSocketData {
    SLWebSocket* ws;
    worker_t* worker;
};

/** Global atomic variables and data structures (all thread safe) */
/** these variables mainly stores the metrics */
inline std::atomic<int> globalConnectionCounter(0);
/**
 * Per-worker delivery counters.
 *
 * These used to be two process-wide atomics incremented on EVERY publish by
 * EVERY worker, so at millions of publishes/s the two cache lines holding them
 * ping-ponged between cores — pure contention on the hot path, and the likely
 * reason per-core efficiency fell from 404k deliveries/s at 4 cores to 303k at
 * 8. Each worker now bumps its own cache-line-aligned slot and /metrics sums
 * them on read (a read happens once per request, not millions of times a second).
 */
struct alignas(64) WorkerCounters {
    std::atomic<unsigned long long> messagesSent{0};
    std::atomic<unsigned long long> payloadSent{0};
    std::atomic<unsigned long long> droppedMessages{0};
    /** pad to a full cache line so neighbouring workers never share one */
    char padding[64 - (3 * sizeof(std::atomic<unsigned long long>)) % 64];
};
inline WorkerCounters workerCounters[256];

inline std::atomic<unsigned long long> totalConnectionErrors{0}; /** Websocket connections rejected due to some error */
inline std::atomic<unsigned long long> totalFailedApiCalls{0};   /** API calls rejected due to 4XX or 5XX codes */
inline std::atomic<unsigned long long> totalSuccessApiCalls{0};  /** API calls with 2XX code */
inline std::atomic<unsigned long long> totalLMDBWrites{0};       /** Total writes to the LMDB database */
inline std::atomic<unsigned long long> totalSuccessWebhookCalls{0}; /** Total webhook calls */
inline std::atomic<unsigned long long> totalFailedWebhookCalls{0};  /** Total failed webhook calls */
inline std::atomic<bool> isMessagingDisabled(false);

/** Per-worker latency EMA snapshots (indexed by worker position in `workers`,
 *  written by each worker's own thread, averaged by /metrics). A fixed array
 *  because worker_t can't hold an atomic member (it must stay movable for
 *  vector::resize) — 256 comfortably exceeds any realistic core count. */
inline std::atomic<double> workerEmaLatencyMs[256] = {};

/** All connection/room state uses TBB concurrent maps unconditionally. (These work
 *  fine single-threaded too, so the previous SingleThreaded std::unordered_map mirror
 *  and the isMultiThread branching were removed to eliminate ~1000 lines of duplicate,
 *  divergence-prone logic.) */
namespace ThreadSafe {
    inline tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> topics;
    inline tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> bannedConnections;
    inline tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> disabledConnections;
    inline tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>> uidToRoomMapping;
    inline tbb::concurrent_hash_map<std::string, bool> uid;
    inline tbb::concurrent_hash_map<std::string, WebSocketData> connections;
    /** rid -> which workers hold subscribers (see RoomWorkers) */
    inline tbb::concurrent_hash_map<std::string, std::shared_ptr<RoomWorkers>> roomWorkers;
} // namespace ThreadSafe

inline std::shared_mutex registryIterationGuard;

inline std::vector<worker_t> workers;

/** Aggregates for /metrics (summed on read, never on the hot path). */
inline unsigned long long totalMessagesSent() {
    unsigned long long sum = 0;
    for (size_t i = 0; i < workers.size() && i < 256; ++i)
        sum += workerCounters[i].messagesSent.load(std::memory_order_relaxed);
    return sum;
}
inline unsigned long long totalPayloadBytesSent() {
    unsigned long long sum = 0;
    for (size_t i = 0; i < workers.size() && i < 256; ++i)
        sum += workerCounters[i].payloadSent.load(std::memory_order_relaxed);
    return sum;
}
inline unsigned long long totalDroppedMessages() {
    unsigned long long sum = 0;
    for (size_t i = 0; i < workers.size() && i < 256; ++i)
        sum += workerCounters[i].droppedMessages.load(std::memory_order_relaxed);
    return sum;
}

/** Worker masks address workers by bit position, so this many workers at most
 *  get the optimisation; beyond it the publish path falls back to waking all. */
inline constexpr size_t MAX_MASKED_WORKERS = 64;

/** Cap on an admin/REST request body. Without it a client can stream unbounded
 *  bytes into the per-request accumulation string; the largest legitimate body
 *  is a bulk ban/broadcast list, which is far below this. */
inline constexpr size_t MAX_REQUEST_BODY_BYTES = 8u * 1024u * 1024u;

/** Index of a worker within the global `workers` vector. */
inline size_t workerIndex(const worker_t* w) {
    return (size_t)(w - ::workers.data());
}

/**
 * Register one subscriber of `rid` on worker `idx` and return the shared record
 * (which the caller stores in its socket-local map). Owner-thread only.
 */
inline std::shared_ptr<RoomWorkers> roomWorkersAdd(const std::string& rid, size_t idx) {
    /** The accessor (a per-key write lock) is held across the whole mutation so
     *  add and remove are serialised for this room. Releasing it early would let
     *  a concurrent remove observe mask == 0 and erase the entry in between this
     *  insert and its bit-set — orphaning this subscriber's record while later
     *  publishers create a fresh one, which silently loses messages. */
    tbb::concurrent_hash_map<std::string, std::shared_ptr<RoomWorkers>>::accessor acc;
    if (ThreadSafe::roomWorkers.insert(acc, rid)) {
        acc->second = std::make_shared<RoomWorkers>(::workers.size());
    }
    std::shared_ptr<RoomWorkers> rw = acc->second;

    if (idx < MAX_MASKED_WORKERS && idx < rw->counts.size()) {
        if (rw->counts[idx].fetch_add(1, std::memory_order_relaxed) == 0) {
            rw->mask.fetch_or(1ULL << idx, std::memory_order_release);
        }
    }
    return rw;
}

/** Mask of workers holding a subscriber of `rid` (0 when the room is unknown).
 *  For callers that do not already hold the room's RoomWorkers pointer — e.g.
 *  the join/leave broadcasts, which fire per subscribe rather than per message. */
inline uint64_t roomWorkerMaskFor(const std::string& rid) {
    tbb::concurrent_hash_map<std::string, std::shared_ptr<RoomWorkers>>::const_accessor acc;
    if (!ThreadSafe::roomWorkers.find(acc, rid)) {
        return 0;
    }
    return acc->second->mask.load(std::memory_order_acquire);
}

/** Drop one subscriber of `rid` on worker `idx`; erases the record when the last
 *  subscriber anywhere leaves. Owner-thread only. */
inline void roomWorkersRemove(const std::string& rid, size_t idx) {
    /** accessor held across the mutation — see roomWorkersAdd */
    tbb::concurrent_hash_map<std::string, std::shared_ptr<RoomWorkers>>::accessor acc;
    if (!ThreadSafe::roomWorkers.find(acc, rid)) {
        return;
    }
    std::shared_ptr<RoomWorkers> rw = acc->second;

    if (idx < MAX_MASKED_WORKERS && idx < rw->counts.size()) {
        if (rw->counts[idx].fetch_sub(1, std::memory_order_relaxed) == 1) {
            rw->mask.fetch_and(~(1ULL << idx), std::memory_order_release);
            if (rw->mask.load(std::memory_order_acquire) == 0) {
                ThreadSafe::roomWorkers.erase(acc); /** room is empty everywhere */
            }
        }
    }
}

/**
 * Guards ITERATION of the registry maps above. tbb::concurrent_hash_map tolerates
 * concurrent find/insert/erase, but traversing it while another thread inserts or
 * erases is undocumented behavior (the admin list endpoints used to do exactly
 * that). Locking rule:
 *   - structural mutations (insert/erase) and value writes on topics,
 *     bannedConnections, disabledConnections, uidToRoomMapping and uid take a
 *     SHARED lock — concurrent with each other, essentially free;
 *   - the rare admin endpoints that iterate those maps take the EXCLUSIVE lock;
 *   - pure find() needs no lock (TBB guarantees find vs mutate);
 *   - `connections` is never iterated and needs no locking.
 * Keep lock scopes tight: never hold this across defers, webhooks, or sends.
 */

/** Topic every connection is subscribed to, for server-wide admin broadcasts.
 *  (The other event-name constants that used to live here were never referenced —
 *  every send site writes the string inline — so they were removed.) */
constexpr const char* BROADCAST = "SOCKETLINK_BROADCAST";

/**
 * Run `fn(ws, worker)` on the event-loop thread that owns `uid`'s websocket, but
 * only if that connection is still alive when the deferred lambda actually runs.
 *
 * Capturing a raw SLWebSocket* into loop_->defer() (or touching one directly from
 * an HTTP handler on another thread) is a use-after-free waiting to happen: the
 * socket can close and be freed between the lookup and the lambda executing.
 * Instead we capture the uid and re-look it up in ThreadSafe::connections INSIDE
 * the deferred lambda. Since .close erases the entry on the owner thread — the
 * same thread this lambda runs on — a successful lookup here guarantees the
 * socket stays valid for the whole synchronous call to `fn`.
 */
template <typename F> void runOnOwnerThread(worker_t* worker, const std::string& uid, F&& fn) {
    worker->loop_->defer([uid, fn = std::forward<F>(fn)]() {
        SLWebSocket* ws = nullptr;
        worker_t* owner = nullptr;
        {
            tbb::concurrent_hash_map<std::string, WebSocketData>::const_accessor accessor;
            if (!ThreadSafe::connections.find(accessor, uid)) {
                return; /** connection closed in the meantime — nothing to do */
            }
            ws = accessor->second.ws;
            owner = accessor->second.worker;
        }
        fn(ws, owner);
    });
}
