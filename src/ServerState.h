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

/* ws->getUserData returns one of these */
struct PerSocketData {
    std::string key;
    std::string uid;
    std::string metadata;

    /**
     * This socket's subscriptions (rid -> room type). OWNER-THREAD ONLY: every
     * mutation site (openConnection/closeConnection) runs on the socket's event
     * loop (REST/ban callers get there via runOnOwnerThread), so the per-message
     * hot path reads this plain map with no locks or atomics at all. The global
     * ThreadSafe::uidToRoomMapping is maintained in the same code paths and
     * serves only cross-thread readers (REST validation, admin listings).
     */
    std::unordered_map<std::string, uint8_t> rooms;

    /**
     * true - sending allowed
     * false - sending not allowed
     */
    bool sendingAllowed = true;
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
inline std::atomic<unsigned long long> globalMessagesSent{0};
inline std::atomic<unsigned long long> totalPayloadSent{0};
inline std::atomic<unsigned long long> totalConnectionErrors{0};    /** Websocket connections rejected due to some error */
inline std::atomic<unsigned long long> totalFailedApiCalls{0};      /** API calls rejected due to 4XX or 5XX codes */
inline std::atomic<unsigned long long> totalSuccessApiCalls{0};     /** API calls with 2XX code */
inline std::atomic<unsigned long long> totalLMDBWrites{0};          /** Total writes to the LMDB database */
inline std::atomic<unsigned long long> totalSuccessWebhookCalls{0}; /** Total webhook calls */
inline std::atomic<unsigned long long> totalFailedWebhookCalls{0};  /** Total failed webhook calls */
inline std::atomic<unsigned long long> droppedMessages{0};
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
} // namespace ThreadSafe

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
inline std::shared_mutex registryIterationGuard;

inline std::vector<worker_t> workers;

/** Sending Constants */
constexpr const char* ROOM_NAME_INVALID = "ROOM_NAME_INVALID";
constexpr const char* API_KEY_INVALID = "API_KEY_INVALID";
constexpr const char* CONNECTION_LIMIT_EXCEEDED = "CONNECTION_LIMIT_EXCEEDED";
constexpr const char* SOMEONE_JOINED_THE_ROOM = "SOMEONE_JOINED_THE_ROOM";
constexpr const char* CONNECTED_TO_ROOM = "CONNECTED_TO_ROOM";
constexpr const char* SOMEONE_LEFT_THE_ROOM = "SOMEONE_LEFT_THE_ROOM";
constexpr const char* YOU_ARE_RATE_LIMITED = "YOU_ARE_RATE_LIMITED";
constexpr const char* RATE_LIMIT_LIFTED = "RATE_LIMIT_LIFTED";
constexpr const char* BROADCAST = "SOCKETLINK_BROADCAST";
constexpr const char* YOU_HAVE_BEEN_BANNED = "YOU_HAVE_BEEN_BANNED";

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
