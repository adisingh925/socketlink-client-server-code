/**
 * worker_t::work(): one uWS event loop per thread — the websocket behavior
 * (upgrade/open/message/drain/close) and every REST endpoint.
 */
#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "json.hpp"
#include "simdjson.h"

#include "Config.h"
#include "LmdbStore.h"
#include "Logging.h"
#include "MemoryGuard.h"
#include "MySQLHandler.h"
#include "RoomLifecycle.h"
#include "ServerState.h"
#include "Util.h"
#include "Webhooks.h"

/** Thread local variables (latency EMA probe + reused JSON parser) */

thread_local double localEma = 0.0;
thread_local std::chrono::time_point<std::chrono::high_resolution_clock> threadTimestamp =
    std::chrono::high_resolution_clock::now();
static thread_local simdjson::ondemand::parser parser;

/** smoothing factor */
constexpr double alpha = 0.05;

/** calculate latency for each thread */
void update_ema(double newLatency) {
    localEma = alpha * newLatency + (1 - alpha) * localEma;
}

/* ------------------------------------------------------------------------- *
 *  REST handler helpers
 *
 *  Every endpoint used to repeat the same three blocks by hand: an abort-flag
 *  prologue, an api-key check with its rejection response, and a corked JSON
 *  reply guarded by the abort flag. That was ~100 copies of the reply pattern
 *  alone, and the copies had drifted — eight rejections answered a bare "403"
 *  where the rest answered "401 Unauthorized". These helpers make the shape
 *  impossible to get wrong; the endpoint bodies below now read as logic.
 * ------------------------------------------------------------------------- */

/** Response type for the plaintext (non-TLS) app. */
using SLRes = uWS::HttpResponse<false>;

/** (MAX_REQUEST_BODY_BYTES lives in ServerState.h) */

/** Install the abort flag. uWS may abort a request at any time; every write must
 *  be guarded by this, and it must outlive the handler (async completions). */
static std::shared_ptr<bool> makeAbortFlag(SLRes* res) {
    auto aborted = std::make_shared<bool>(false);
    res->onAborted([aborted]() {
        *aborted = true;
        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
    });
    return aborted;
}

/** Send a JSON reply, unless the client already went away. The api-call counters
 *  follow the status: 2xx counts as success, anything else as failure. */
static void replyJson(SLRes* res, const std::shared_ptr<bool>& aborted, const char* status, std::string body) {
    if (*aborted) {
        return;
    }
    (status[0] == '2' ? totalSuccessApiCalls : totalFailedApiCalls).fetch_add(1, std::memory_order_relaxed);
    res->cork([res, status, body = std::move(body)]() {
        res->writeStatus(status);
        res->writeHeader("Content-Type", "application/json");
        res->end(body);
    });
}

/** Reject with 500 — the shared body of every handler's outermost catch. */
static void replyInternalError(SLRes* res, const std::shared_ptr<bool>& aborted) {
    replyJson(res, aborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
}

/** Reject with 400 for a malformed JSON body — the shared body of every
 *  onData catch. */
static void replyInvalidJson(SLRes* res, const std::shared_ptr<bool>& aborted) {
    replyJson(res, aborted, "400 Bad Request", R"({"message": "Invalid JSON format!"})");
}

/** True when the request carries the admin key; otherwise answers 401 and
 *  returns false so the caller can simply `return`. */
static bool requireAdminKey(SLRes* res, uWS::HttpRequest* req, const std::shared_ptr<bool>& aborted) {
    if (constantTimeEquals(req->getHeader("api-key"), UserData::getInstance().adminApiKey)) {
        return true;
    }
    log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");
    replyJson(res, aborted, "401 Unauthorized", R"({"message": "Unauthorized access, Invalid API key!"})");
    return false;
}

/** Same for the client key (WS/pub-sub clients). */
static bool requireClientKey(SLRes* res, uWS::HttpRequest* req, const std::shared_ptr<bool>& aborted) {
    if (constantTimeEquals(req->getHeader("api-key"), UserData::getInstance().clientApiKey)) {
        return true;
    }
    log(LogLevel::WARN, "Client API: request rejected (invalid client api key)");
    replyJson(res, aborted, "401 Unauthorized", R"({"message": "Unauthorized access, Invalid API key!"})");
    return false;
}

/* uWebSocket worker thread function. */
void worker_t::work() {
    /** Fixed plaintext HTTP/WS listen port. */
    const int listenPort = SL_LISTEN_PORT;

    /* Every thread has its own Loop, and uWS::Loop::get() returns the Loop for current thread.*/
    loop_ = uWS::Loop::get();

    /* uWS::App object / instance is used in uWS::Loop::defer(lambda_function).
   * Plaintext: TLS is terminated upstream (load balancer). No cert needed. */
    app_ = std::make_shared<SLApp>(SLApp());

    /** Periodic LMDB flush (1s): the write batch is thread-local, so on a quiet
     *  worker a partially-filled batch would otherwise sit in memory indefinitely —
     *  invisible to readers until the next fanned-out flush and lost outright on a
     *  crash. An empty batch makes this a no-op. */
    {
        struct us_timer_t* lmdbFlushTimer = us_create_timer((struct us_loop_t*)loop_, 0, 0);
        us_timer_set(lmdbFlushTimer, [](struct us_timer_t*) { write_worker("", "", true); }, 1000, 1000);
    }

    /* Very simple WebSocket broadcasting echo server */
    app_->ws<PerSocketData>(
            "/*",
            {/* Settings */
             .compression = uWS::DISABLED,
             .maxPayloadLength = UserData::getInstance().msgSizeAllowedInBytes,
             .idleTimeout = UserData::getInstance().idleTimeoutInSeconds,
             .maxBackpressure = UserData::getInstance().maxBackpressureInBytes,
             .closeOnBackpressureLimit = false,
             .resetIdleTimeoutOnSend = true,
             .sendPingsAutomatically = true,
             .maxLifetime = UserData::getInstance().maxLifetimeInMinutes,

             /* Handlers */
             .upgrade =
                 [](auto* res, auto* req, auto* context) {
                     struct UpgradeData {
                         std::string secWebSocketKey;
                         std::string secWebSocketProtocol;
                         std::string secWebSocketExtensions;
                         std::string key;
                         std::string uid;
                         std::string metadata;
                         struct us_socket_context_t* context;
                         decltype(res) httpRes;
                         bool aborted = false;
                     };

                     /** Owned for the (synchronous) lifetime of this handler; freed automatically
         *  on every return path. Previously heap-allocated with `new` and never
         *  deleted -> one leak per connection attempt. */
                     auto upgradeData = std::unique_ptr<UpgradeData>(new UpgradeData{
                         std::string(req->getHeader("sec-websocket-key")),
                         std::string(req->getHeader("sec-websocket-protocol")),
                         std::string(req->getHeader("sec-websocket-extensions")),
                         std::string(req->getHeader("api-key")),
                         std::string(req->getHeader("uid").data() ? req->getHeader("uid") : ""),
                         std::string(req->getHeader("metadata").data() ? req->getHeader("metadata") : ""), context,
                         res});

                     res->onAborted([ud = upgradeData.get()]() { ud->aborted = true; });

                     if (upgradeData->uid.empty() || upgradeData->uid.length() > 4096) {
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("400 Bad Request");
                             res->writeHeader("Content-Type", "application/json");
                             res->end("INVALID_UID");
                         });

                         return;
                     }

                     if (upgradeData->metadata.length() > 1024) {
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("413 Payload Too Large");
                             res->writeHeader("Content-Type", "application/json");
                             res->end("INVALID_METADATA");
                         });

                         return;
                     }

                     {
                         /** Check if the user is banned and reject the connection */
                         tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor
                             bannedAccessor;
                         if (ThreadSafe::bannedConnections.find(bannedAccessor, "global")) {
                             /** Access the inner map */
                             tbb::concurrent_hash_map<std::string, bool>& inner_map = bannedAccessor->second;

                             /** Accessor for the inner map */
                             tbb::concurrent_hash_map<std::string, bool>::accessor innerAccessor;

                             /** Check if the user UID is banned in the inner map */
                             if (inner_map.find(innerAccessor, upgradeData->uid)) {

                                 totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);
                                 log(LogLevel::DEBUG, "Connection rejected (banned): uid=", upgradeData->uid);

                                 res->cork([res]() {
                                     res->writeStatus("403 Forbidden");
                                     res->writeHeader("Content-Type", "application/json");
                                     res->end("CONNECTION_BANNED");
                                 });

                                 return;
                             }
                         }
                     }

                     {
                         /** check if a connection is already there with the same uid (thread safe) */
                         tbb::concurrent_hash_map<std::string, bool>::const_accessor accessor;
                         if (ThreadSafe::uid.find(accessor, upgradeData->uid)) {

                             totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);
                             log(LogLevel::DEBUG, "Connection rejected (duplicate uid): uid=", upgradeData->uid);

                             res->cork([res]() { res->writeStatus("409 Conflict")->end("UID_ALREADY_EXIST"); });

                             return;
                         }
                     }

                     /** Check if API key is valid or not */
                     if (!constantTimeEquals(upgradeData->key, UserData::getInstance().clientApiKey)) {
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);
                         log(LogLevel::WARN, "Connection rejected (invalid client api key): uid=", upgradeData->uid);

                         res->cork([res]() { res->writeStatus("401 Unauthorized")->end("INVALID_API_KEY"); });

                         return;
                     }

                     /** Per-user token (no-op while connection_token_secret is unset): the uid
         *  header is otherwise client-asserted, so one leaked client key could
         *  impersonate any user. */
                     if (!verifyConnectionToken(upgradeData->uid, req->getHeader("token"))) {
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);
                         log(LogLevel::WARN, "Connection rejected (invalid token): uid=", upgradeData->uid);

                         res->cork([res]() { res->writeStatus("401 Unauthorized")->end("INVALID_TOKEN"); });

                         return;
                     }

                     /** Shed new connections while under memory pressure. Without this the
         *  process is OOM-killed once admissions outrun the memory budget (a
         *  1 GB container died at ~50k connections) — killing every established
         *  connection too. Rejecting here keeps the server alive and serving. */
                     if (admissionPaused()) {
                         countMemoryRejection();
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                         static std::atomic<unsigned long long> memRejections{0};
                         if (memRejections.fetch_add(1, std::memory_order_relaxed) % 1000 == 0) {
                             log(LogLevel::WARN, "Rejecting connections: memory pressure (total rejected: ",
                                 memoryRejectionCount(), ")");
                         }

                         res->cork([res]() {
                             res->writeStatus("503 Service Unavailable")->end("SERVER_UNDER_MEMORY_PRESSURE");
                         });

                         return;
                     }

                     /** Reserve a connection slot atomically so the limit is a HARD cap with no
         *  overshoot. Previously the check (here) and the increment (in .open) were at
         *  different lifecycle points, so concurrent upgrades could all pass the check
         *  before any of them counted, letting the server exceed `connections`.
         *  fetch_add returns the PREVIOUS value; if we were already at the limit, give
         *  the slot back and reject. The slot is released in .close on the normal path,
         *  or in the else branch below if the request aborts before it is upgraded. */
                     if (globalConnectionCounter.fetch_add(1, std::memory_order_relaxed) >=
                         UserData::getInstance().connections) {
                         globalConnectionCounter.fetch_sub(1, std::memory_order_relaxed);
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                         /** important operational signal, but rate-limited: sustained overload
             *  would otherwise emit one WARN per rejected attempt */
                         static std::atomic<unsigned long long> limitRejections{0};
                         if (limitRejections.fetch_add(1, std::memory_order_relaxed) % 1000 == 0) {
                             log(LogLevel::WARN, "Connection limit reached (", UserData::getInstance().connections,
                                 "): rejecting new connections (total rejected: ",
                                 limitRejections.load(std::memory_order_relaxed), ")");
                         }

                         res->cork([res]() {
                             res->writeStatus("503 Service Unavailable")->end("MAX_CONNECTION_LIMIT_REACHED");
                         });

                         return;
                     }

                     if (!upgradeData->aborted) {
                         upgradeData->httpRes->cork([ud = upgradeData.get()]() {
                             ud->httpRes->template upgrade<PerSocketData>(
                                 {
                                     /* We initialize PerSocketData struct here */
                                     .key = ud->key,
                                     .uid = ud->uid,
                                     .metadata = ud->metadata,
                                 },
                                 ud->secWebSocketKey, ud->secWebSocketProtocol, ud->secWebSocketExtensions,
                                 ud->context);
                         });
                     } else {
                         /** Slot was reserved above, but the request aborted before upgrading, so
             *  .open/.close will never run to release it -- release it here. */
                         globalConnectionCounter.fetch_sub(1, std::memory_order_relaxed);
                     }
                 },
             .open =
                 [this](auto* ws) {
                     WebSocketData data;
                     data.ws = ws;
                     data.worker = this;

                     std::string userId = ws->getUserData()->uid;

                     /** The connection slot was already reserved atomically in the upgrade handler
         *  (hard limit) and is released in .close; do not count again here. */

                     {
                         tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
                         bool inserted = ThreadSafe::connections.insert(conn_accessor, userId);
                         if (inserted) {
                             conn_accessor->second = std::move(data);
                         } else {
                             /** UID already exists, something went wrong */
                             ws->end();
                             return;
                         }
                     }

                     {
                         /** structural mutation of an iterated registry map */
                         std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                         tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;
                         if (ThreadSafe::uid.insert(user_accessor, userId)) {
                             user_accessor->second = true;
                         } else {
                             /** UID already exists, something went wrong */
                             ws->end();
                             return;
                         }
                     }

                     /** Bound this socket's kernel send/receive buffers. Linux auto-tunes
         *  them upward under load (tcp_wmem max is megabytes) and that memory is
         *  charged to the container's cgroup, where it dominates at high
         *  connection counts — it is what OOM-killed a 1 GB container even after
         *  admission control was in place, because no amount of refusing NEW
         *  connections reclaims buffers held by established ones. */
                     {
                         /** 8 KB (the kernel doubles it internally, so ~16 KB each
             *  way). Measured: cgroup `sock` was the term that ran away —
             *  55 MiB -> 293 MiB and beyond as a single CPU fell behind on
             *  draining — because Linux autotunes send buffers into the
             *  megabytes. Pair this with net.ipv4.tcp_mem as a hard ceiling. */
                         static const int sndBuf = []() {
                             const char* e = std::getenv("SL_SOCKET_SNDBUF");
                             int v = e ? std::atoi(e) : 8192;
                             return v > 0 ? v : 8192;
                         }();
                         int fd = (int)(intptr_t)ws->getNativeHandle();
                         if (fd >= 0) {
                             setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndBuf, sizeof(sndBuf));
                             setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sndBuf, sizeof(sndBuf));
                         }
                     }

                     log(LogLevel::DEBUG, "Connection open: uid=", userId, " (",
                         globalConnectionCounter.load(std::memory_order_relaxed), " total)");

                     ws->subscribe(userId);
                     ws->subscribe(BROADCAST);
                 },
             .message =
                 [this](auto* ws, std::string_view message, uWS::OpCode opCode) {
                     auto& userData = *ws->getUserData();
                     const auto& uid = userData.uid;

                     auto sendMessagingDisabled = [&]() {
                         ws->send("{\"data\":\"MESSAGING_DISABLED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                     };

                     /** checking if the message sending is disabled globally at the server level */
                     if (isMessagingDisabled.load(std::memory_order_relaxed)) {
                         sendMessagingDisabled();
                         return;
                     }

                     /** checking if the messaging is disabled for a particular connection at global level.
         *  Fast path: skip the hash lookup + bucket lock entirely when nobody is disabled
         *  (empty() reads an O(1) size counter, no hashing/locking). */
                     if (!ThreadSafe::disabledConnections.empty()) {
                         /** Check if messaging is disabled for the user */
                         tbb::concurrent_hash_map<
                             std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor outer_accessor;
                         tbb::concurrent_hash_map<std::string, bool>::const_accessor inner_accessor;

                         if (ThreadSafe::disabledConnections.find(outer_accessor, "global") &&
                             outer_accessor->second.find(inner_accessor, uid)) {
                             sendMessagingDisabled();
                             return;
                         }
                     }

                     if (userData.sendingAllowed) {
                         /** check if the backpressure exceeded the given limit */
                         if (ws->getBufferedAmount() > UserData::getInstance().maxBackpressureInBytes) {
                             ws->send("{\"data\":\"YOU_ARE_RATE_LIMITED\",\"source\":\"server\"}", uWS::OpCode::TEXT,
                                      true);
                             workerCounters[workerIndex(this)].droppedMessages.fetch_add(
                                 1, std::memory_order_relaxed);
                             userData.sendingAllowed = false;
                         } else {
                             auto sendInvalidJson = [&]() {
                                 ws->send(R"({"data":"INVALID_JSON","source":"server"})", uWS::OpCode::TEXT, true);
                             };

                             try {
                                 simdjson::ondemand::document parsedData;

                                 /** simdjson (ondemand) reads up to SIMDJSON_PADDING bytes past the end of
                     *  the document as scratch space. The incoming `message` is a string_view
                     *  owned by uWebSockets and offers no such trailing padding, so parsing it
                     *  in place would be an out-of-bounds read. Copy it into a reused thread-local
                     *  buffer whose capacity always includes the required padding. */
                                 static thread_local std::string jsonBuffer;
                                 jsonBuffer.reserve(message.size() + simdjson::SIMDJSON_PADDING);
                                 jsonBuffer.assign(message.data(), message.size());

                                 if (auto error =
                                         parser.iterate(jsonBuffer.data(), jsonBuffer.size(), jsonBuffer.capacity())
                                             .get(parsedData);
                                     error) {
                                     sendInvalidJson();
                                     return;
                                 }

                                 /** a "timestamp" field means this is a reply to a latency probe */
                                 if (auto timeField = parsedData["timestamp"]; !timeField.error()) {
                                     int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                           std::chrono::high_resolution_clock::now() - threadTimestamp)
                                                           .count();

                                     update_ema(elapsed);

                                     /** publish this thread's EMA so /metrics can average across
                      *  workers instead of reporting whichever thread served it */
                                     size_t workerIdx = workerIndex(this);
                                     if (workerIdx < 256) {
                                         workerEmaLatencyMs[workerIdx].store(localEma, std::memory_order_relaxed);
                                     }

                                     return;
                                 }

                                 std::string rid;
                                 if (auto ridField = parsedData["rid"]; !ridField.error()) {
                                     rid = std::string(ridField.get_string().value());
                                 } else {
                                     sendInvalidJson();
                                     return;
                                 }

                                 /** string_view into the parse buffer, not a copy: this is the
                     *  largest field on the hot path and everything downstream
                     *  (escaping, persistence, webhook) accepts a view. Named
                     *  msgBody because `message` is the enclosing handler's
                     *  parameter — the old local shadowed it. */
                                 std::string_view msgBody;
                                 if (auto msgField = parsedData["message"]; !msgField.error()) {
                                     msgBody = msgField.get_string().value();
                                 } else {
                                     sendInvalidJson();
                                     return;
                                 }

                                 uint8_t roomType = 255;

                                 auto sendNoSubscriptionFound = [&]() {
                                     ws->send(R"({"data":"NO_SUBSCRIPTION_FOUND","source":"server"})",
                                              uWS::OpCode::TEXT, true);
                                 };

                                 /** which workers actually hold subscribers of this room */
                                 uint64_t workerMask = 0;

                                 {
                                     /** the sender must already be subscribed to `rid`; fetch its room type
                      *  and the room's worker mask from the SOCKET-LOCAL map (mutated
                      *  only on this thread by openConnection/closeConnection) — no
                      *  locks, no shared-map lookup, no atomics beyond the mask load */
                                     auto roomIt = userData.rooms.find(rid);
                                     if (roomIt == userData.rooms.end()) {
                                         sendNoSubscriptionFound();
                                         return;
                                     }

                                     roomType = roomIt->second.roomType;
                                     if (roomIt->second.workers) {
                                         workerMask =
                                             roomIt->second.workers->mask.load(std::memory_order_acquire);
                                     }
                                 }

                                 /** Fast path: skip the room-disabled lookup when nobody is disabled anywhere. */
                                 if (!ThreadSafe::disabledConnections.empty()) {
                                     tbb::concurrent_hash_map<
                                         std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor
                                         outer_accessor;
                                     tbb::concurrent_hash_map<std::string, bool>::const_accessor inner_accessor;

                                     if ((ThreadSafe::disabledConnections.find(outer_accessor, rid) &&
                                          outer_accessor->second.find(inner_accessor, uid))) {
                                         ws->send("{\"data\":\"MESSAGING_DISABLED\",\"source\":\"server\"}",
                                                  uWS::OpCode::TEXT, true);
                                         return;
                                     }
                                 }

                                 /** Build the published envelope once, escaping the user-controlled
                     *  message and room id so a quote/backslash/control char cannot break
                     *  out of the JSON string or inject fields. Built in a reused
                     *  thread-local buffer, so a room served entirely by this worker
                     *  publishes with ZERO heap allocations. */
                                 static thread_local std::string envelope;
                                 envelope.clear();
                                 envelope.reserve(msgBody.size() + rid.size() + 40);
                                 envelope += "{\"data\":\"";
                                 appendJsonEscaped(envelope, msgBody);
                                 envelope += "\",\"source\":\"user\",\"rid\":\"";
                                 appendJsonEscaped(envelope, rid);
                                 envelope += "\"}";

                                 /** publish locally on this worker */
                                 ws->publish(rid, envelope, opCode, true);

                                 const size_t selfIdx = workerIndex(this);
                                 /** SL_NO_WORKER_MASK=1 restores the old wake-everyone behaviour,
                      *  for A/B measurement of this optimisation */
                                 static const bool maskDisabled = std::getenv("SL_NO_WORKER_MASK") != nullptr;
                                 const bool maskUsable = !maskDisabled && ::workers.size() <= MAX_MASKED_WORKERS;

                                 /** which OTHER workers need this message */
                                 uint64_t remoteMask = maskUsable ? workerMask : ~0ULL;
                                 if (::workers.size() < MAX_MASKED_WORKERS) {
                                     remoteMask &= (1ULL << ::workers.size()) - 1ULL;
                                 }
                                 remoteMask &= ~(1ULL << selfIdx);

                                 /** Only pay for the shared copies when there is somewhere to send
                     *  them; a room confined to this worker skips both allocations. */
                                 if (remoteMask != 0) {
                                     auto data = std::make_shared<std::string>(envelope);
                                     auto ridShared = std::make_shared<std::string>(rid);

                                     for (size_t wi = 0; wi < ::workers.size(); ++wi) {
                                         if (!(remoteMask & (1ULL << wi))) {
                                             continue;
                                         }
                                         worker_t& w = ::workers[wi];
                                         w.loop_->defer([&w, data, ridShared, opCode]() {
                                             w.app_->publish(*ridShared, *data, opCode, true);

                                             /** count THIS worker's local subscribers too, so the
                              *  messages_sent/payload metrics reflect true cross-worker
                              *  fan-out (previously only the publisher's worker counted
                              *  and the totals undercounted by ~worker-count) */
                                             unsigned int subs = w.app_->numSubscribers(*ridShared);
                                             WorkerCounters& wc = workerCounters[workerIndex(&w)];
                                             wc.messagesSent.fetch_add(static_cast<unsigned long long>(subs),
                                                                       std::memory_order_relaxed);
                                             wc.payloadSent.fetch_add(static_cast<unsigned long long>(data->size()) *
                                                                          static_cast<unsigned long long>(subs),
                                                                      std::memory_order_relaxed);
                                         });
                                     }
                                 }

                                 /** send latency message to the current websocket, random selection */
                                 auto now = std::chrono::high_resolution_clock::now();
                                 auto elapsed =
                                     std::chrono::duration_cast<std::chrono::seconds>(now - threadTimestamp).count();

                                 if (elapsed > 10) {
                                     ws->send(R"({"source":"latency"})", uWS::OpCode::TEXT, true);
                                     threadTimestamp = now;
                                 }

                                 /** numSubscribers counts the publisher too, but uWS does not
                     *  echo a publish back to the publishing socket — counting it
                     *  inflated messages_sent by roughly room_size/(room_size-1)
                     *  (11% for rooms of 10). Remote workers need no such
                     *  adjustment: the publisher is not subscribed there. */
                                 unsigned int localSubs = app_->numSubscribers(rid);
                                 unsigned int subscribers = localSubs > 0 ? localSubs - 1 : 0;
                                 workerCounters[selfIdx].messagesSent.fetch_add(
                                     static_cast<unsigned long long>(subscribers), std::memory_order_relaxed);
                                 workerCounters[selfIdx].payloadSent.fetch_add(
                                     static_cast<unsigned long long>(envelope.size()) *
                                         static_cast<unsigned long long>(subscribers),
                                     std::memory_order_relaxed);

                                 /** cache rooms persist their messages (LMDB / SQL) */
                                 if (roomType == static_cast<uint8_t>(Rooms::PUBLIC_CACHE) ||
                                     roomType == static_cast<uint8_t>(Rooms::PRIVATE_CACHE) ||
                                     roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) ||
                                     roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)) {
                                     /** store the latest message under the room id (batched; the read
                         *  endpoint forces a flush before reading) */
                                     write_worker(rid, std::string(msgBody));
                                     totalLMDBWrites.fetch_add(1, std::memory_order_relaxed);

                                     /** SQL integration works in cache channels only */
                                     if (getFeatureStatus(Features::ENABLE_MYSQL_INTEGRATION) == 1) {
                                         /** hand the row to the dedicated writer thread — the
                          *  blocking batched INSERT no longer runs on this loop */
                                         MySQLWriter::getInstance().enqueue(getCurrentSQLTime(), std::string(msgBody),
                                                                            uid, rid);
                                     }
                                 }

                                 if (getWebhookStatus(Webhooks::ON_MESSAGE) == 1) {
                                     std::ostringstream payload;
                                     payload << "{\"event\":\"ON_MESSAGE\", " << "\"uid\":\"" << jsonEscape(uid)
                                             << "\", " << "\"rid\":\"" << jsonEscape(rid) << "\", " << "\"message\":\""
                                             << jsonEscape(msgBody) << "\"}";

                                     std::string body = payload.str();

                                     sendHTTPSPOSTRequestFireAndForget(UserData::getInstance().webHookBaseUrl,
                                                                       UserData::getInstance().webhookPath, body, {});
                                 }
                             } catch (const simdjson::simdjson_error& e) {
                                 sendInvalidJson();
                             }
                         }
                     } else {
                         ws->send("{\"data\":\"YOU_ARE_RATE_LIMITED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                         workerCounters[workerIndex(this)].droppedMessages.fetch_add(1, std::memory_order_relaxed);
                     }
                 },
             .dropped =
                 [this](auto* ws, std::string_view /*message*/, uWS::OpCode /*opCode*/) {
                     /** A message was dropped because this connection is over its backpressure
         *  limit. Do NOT ws->send() a notification here: the send buffer is already
         *  full, so that send would itself be dropped and re-invoke this handler
         *  synchronously, recursing until the stack overflows and the server crashes
         *  under sustained backpressure. Just count the drop; the client learns it is
         *  rate-limited via the YOU_ARE_RATE_LIMITED path when it next sends, and via
         *  RATE_LIMIT_LIFTED (in .drain) once its buffer drains. */
                     workerCounters[workerIndex(this)].droppedMessages.fetch_add(1, std::memory_order_relaxed);

                     /** Under memory pressure, SHED this connection instead of holding its
         *  buffers. Refusing new connections cannot reclaim memory already
         *  committed to established ones, which is why the adaptive cap has to
         *  grow so cautiously — this is the missing half. A socket reaching
         *  .dropped is by definition failing to keep up, so it is both the
         *  cheapest to lose and the most expensive to keep. */
                     if (admissionPaused()) {
                         static std::atomic<unsigned long long> shed{0};
                         unsigned long long n = shed.fetch_add(1, std::memory_order_relaxed);
                         if (n % 1000 == 0) {
                             log(LogLevel::WARN, "Memory pressure: closing backpressured connections (total shed: ",
                                 n + 1, ")");
                         }
                         countConnectionShed();
                         ws->end(1013 /* try again later */, "SERVER_UNDER_MEMORY_PRESSURE");
                     }
                 },
             .drain =
                 [](auto* ws) {
                     /** only notify clients that were actually rate-limited */
                     if (!ws->getUserData()->sendingAllowed &&
                         ws->getBufferedAmount() < (UserData::getInstance().maxBackpressureInBytes / 2)) {
                         ws->getUserData()->sendingAllowed = true;
                         ws->send("{\"data\":\"RATE_LIMIT_LIFTED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                     }
                 },
             .close =
                 [this](auto* ws, int /* code */, std::string_view /* message */) {
                     std::string userId = ws->getUserData()->uid;

                     /** release the reserved connection slot (reserved in the upgrade handler) */
                     globalConnectionCounter.fetch_sub(1, std::memory_order_relaxed);

                     log(LogLevel::DEBUG, "Connection closed: uid=", userId, " (",
                         globalConnectionCounter.load(std::memory_order_relaxed), " remaining)");

                     /** A socket that lost the duplicate-uid race in .open gets end()ed while
         *  the WINNER's registry entries are live under the same uid — so only
         *  tear down the uid-keyed state if it belongs to THIS socket, otherwise
         *  this close would silently deregister the surviving connection. */
                     bool ownedRegistryEntry = false;

                     {
                         tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
                         if (ThreadSafe::connections.find(conn_accessor, userId) && conn_accessor->second.ws == ws) {
                             ThreadSafe::connections.erase(conn_accessor);
                             ownedRegistryEntry = true;
                         }
                     }

                     if (ownedRegistryEntry) {
                         /** structural mutation of an iterated registry map */
                         std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                         tbb::concurrent_hash_map<std::string, bool>::accessor uid_accessor;
                         if (ThreadSafe::uid.find(uid_accessor, userId)) {
                             ThreadSafe::uid.erase(uid_accessor);
                         }
                     }

                     ws->unsubscribe(userId);
                     ws->unsubscribe(BROADCAST);

                     /** close every room subscription for this uid, then drop the uid mapping.
         *  Iterate the SOCKET-LOCAL map (owner thread; closeConnection with
         *  isClosed=true doesn't mutate it) instead of the global one — no TBB
         *  accessor is held across the closeConnection calls. */
                     if (ownedRegistryEntry) {
                         const size_t myIdx = workerIndex(this);
                         for (auto& entry : ws->getUserData()->rooms) {
                             closeConnection(ws, this, entry.first, userId, entry.second.roomType, true);
                             /** closeConnection skips this in the isClosed path, so release
                  *  this worker's claim on each room's publish mask here */
                             roomWorkersRemove(entry.first, myIdx);
                         }
                         ws->getUserData()->rooms.clear();

                         /** drop the global (cross-thread view) mapping for this uid
             *  (structural mutation of an iterated registry map) */
                         std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                         tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor
                             outer_accessor;
                         if (ThreadSafe::uidToRoomMapping.find(outer_accessor, userId)) {
                             ThreadSafe::uidToRoomMapping.erase(outer_accessor);
                         }
                     }
                 }})
        .get("/api/v1/metrics",
             [](auto* res, auto* req) {
                 /** fetch all the server metrics */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     if (!requireAdminKey(res, req, isAborted)) {
                         return;
                     }

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         /** average the per-worker latency EMAs (only workers that have
                          *  measured anything) — previously this reported the EMA of
                          *  whichever thread happened to serve /metrics, usually 0 */
                         double emaSum = 0.0;
                         int emaCount = 0;
                         for (size_t i = 0; i < ::workers.size() && i < 256; ++i) {
                             double v = workerEmaLatencyMs[i].load(std::memory_order_relaxed);
                             if (v > 0.0) {
                                 emaSum += v;
                                 ++emaCount;
                             }
                         }
                         double avgLatencyMs = (emaCount > 0) ? (emaSum / emaCount) : 0.0;

                         res->cork([res, avgLatencyMs]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"connections": )" +
                                      std::to_string(globalConnectionCounter.load(std::memory_order_relaxed)) +
                                      R"(,"messages_sent": )" +
                                      std::to_string(totalMessagesSent()) +
                                      R"(,"total_payload_sent": )" +
                                      std::to_string(totalPayloadBytesSent()) +
                                      R"(,"total_failed_api_calls": )" +
                                      std::to_string(totalFailedApiCalls.load(std::memory_order_relaxed)) +
                                      R"(,"total_success_api_calls": )" +
                                      std::to_string(totalSuccessApiCalls.load(std::memory_order_relaxed)) +
                                      R"(,"total_failed_connection_attempts": )" +
                                      std::to_string(totalConnectionErrors.load(std::memory_order_relaxed)) +
                                      R"(,"total_mysql_db_batch_writes": )" +
                                      std::to_string(totalMysqlDBWrites.load(std::memory_order_relaxed)) +
                                      R"(,"total_local_db_writes": )" +
                                      std::to_string(totalLMDBWrites.load(std::memory_order_relaxed)) +
                                      R"(,"total_success_webhook_calls": )" +
                                      std::to_string(totalSuccessWebhookCalls.load(std::memory_order_relaxed)) +
                                      R"(,"total_failed_webhook_calls": )" +
                                      std::to_string(totalFailedWebhookCalls.load(std::memory_order_relaxed)) +
                                      R"(,"average_latency": )" + std::to_string(avgLatencyMs) +
                                      R"(,"dropped_messages": )" +
                                      std::to_string(totalDroppedMessages()) +
                                      R"(,"dropped_log_lines": )" +
                                      std::to_string(AsyncLogger::getInstance().droppedCount()) +
                                      R"(,"dropped_webhook_events": )" + std::to_string(droppedWebhookCount()) +
                                      R"(,"dropped_db_rows": )" +
                                      std::to_string(MySQLWriter::getInstance().droppedCount()) +
                                      R"(,"memory_working_set_bytes": )" + std::to_string(currentMemoryWorkingSetBytes()) +
                                      R"(,"memory_limit_bytes": )" + std::to_string(memoryLimitBytes()) +
                                      R"(,"admission_paused": )" + (admissionPaused() ? "true" : "false") +
                                      R"(,"rejected_memory_pressure": )" + std::to_string(memoryRejectionCount()) +
                                      R"(,"shed_connections": )" + std::to_string(connectionShedCount()) +
                                      R"(,"connection_limit": )" +
                                      std::to_string(UserData::getInstance().connections) +
                                      R"(,"measured_bytes_per_connection": )" +
                                      std::to_string(measuredBytesPerConnection()) + R"(})");
                         });
                     }
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .post("/api/v1/invalidate",
              [](auto* res, auto* req) {
                  /** update the metadata used by the server */

                  auto isAborted = makeAbortFlag(res);

                  try {
                      std::string_view apiKey = req->getHeader("api-key");

                      /** Admin-key auth (self-hosted: no master shared-secret signature) */
                      if (!requireAdminKey(res, req, isAborted)) {
                          return;
                      }

                      std::string body;

                      body.reserve(1024);

                      res->onData(
                          [res, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
                              if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating */
                        }
                        body.append(data.data(), data.length());

                              if (last) {
                                  try {
                                      /** Apply the new config (admin-key already verified above) */
                                      int action = populateUserData(body);

                                      if (action == 1) {
                                          /** DB connection parameters changed */
                                          MySQLWriter::getInstance().requestReconnect();
                                      } else if (action == -1) {
                                          /** SQL integration disabled: flush, then drop the connection */
                                          MySQLWriter::getInstance().requestDisconnect();
                                      }

                                      log(LogLevel::INFO, "Config updated via /api/v1/invalidate");

                                      replyJson(res, isAborted, "200 OK",
                                                R"({"message": "Metadata invalidated successfully!"})");

                                      if (action == 2) {
                                          log(LogLevel::INFO, "socket-level settings changed: exiting shortly so the "
                                                              "process manager restarts with the new values");
                                          std::thread([]() {
                                              /** let the 200 response flush first */
                                              std::this_thread::sleep_for(std::chrono::seconds(1));

                                              /** flush all persistence BEFORE exiting: per-worker
                       *  thread-local LMDB batches, buffered MySQL rows, then
                       *  a synchronous LMDB sync (MDB_WRITEMAP + exit() would
                       *  otherwise lose recently committed pages). */
                                              for (auto& w : ::workers) {
                                                  w.loop_->defer([&w]() { write_worker("", "", true); });
                                              }
                                              MySQLWriter::getInstance().requestFlush();
                                              std::this_thread::sleep_for(std::chrono::milliseconds(500));
                                              mdb_env_sync(env, 1);

                                              /** _Exit: static destruction with live worker
                       *  threads hangs; everything durable is flushed */
                                              std::_Exit(0);
                                          }).detach();
                                      }
                                  } catch (const std::exception&) {
                                      replyJson(res, isAborted, "400 Bad Request",
                                                R"({"message": "Invalid JSON format!"})");
                                  }
                              }
                          });
                  } catch (const std::exception&) {
                      replyJson(res, isAborted, "500 Internal Server Error",
                                R"({"message": "Internal server error!"})");
                  }
              })
        .get("/api/v1/mysql/sync",
             [](auto* res, auto* req) {
                 /** sync all the data in the buffers to integrated mysql server */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     if (!requireAdminKey(res, req, isAborted)) {
                         return;
                     }

                     if (getFeatureStatus(Features::ENABLE_MYSQL_INTEGRATION) == 0) {
                         replyJson(res, isAborted, "403 Forbidden", R"({"message": "MySQL integration is disabled!"})");

                         return;
                     }

                     MySQLWriter::getInstance().requestFlush();

                     log(LogLevel::INFO, "Admin API: MySQL flush requested via /api/v1/mysql/sync");

                     replyJson(res, isAborted, "200 OK", R"({"message": "MySQL data synced successfully!"})");
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .get("/api/v1/rooms/users/all",
             [this](auto* res, auto* req) {
                 /** fetch all the rooms present on the server */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     if (!requireAdminKey(res, req, isAborted)) {
                         return;
                     }

                     nlohmann::json data = nlohmann::json::array();

                     /** EXCLUSIVE: iterating a registry map is only safe while no thread
                      *  is inserting/erasing (all mutators hold registryIterationGuard shared) */
                     std::unique_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                     for (const auto& [rid, users] : ThreadSafe::topics) {
                         nlohmann::json roomData;
                         roomData["rid"] = rid;

                         std::vector<std::string> userKeys;

                         for (const auto& [uid, _] : users) {
                             userKeys.push_back(uid);
                         }

                         roomData["uid"] = std::move(userKeys);

                         data.push_back(std::move(roomData));
                     }

                     replyJson(res, isAborted, "200 OK", data.dump());
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .get("/api/v1/users/orphan",
             [this](auto* res, auto* req) {
                 /** fetch all the rooms present on the server */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     if (!requireAdminKey(res, req, isAborted)) {
                         return;
                     }

                     std::vector<std::string> orphanUids;

                     /** EXCLUSIVE: iteration vs concurrent insert/erase (see registryIterationGuard) */
                     std::unique_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                     for (auto it = ThreadSafe::uid.begin(); it != ThreadSafe::uid.end(); ++it) {
                         if (it->second) {
                             orphanUids.push_back(it->first);
                         }
                     }

                     nlohmann::json data;
                     data["uid"] = orphanUids;

                     replyJson(res, isAborted, "200 OK", data.dump());
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .post(
            "/api/v1/rooms/users",
            [this](auto* res, auto* req) {
                /** get all the connectiond for a room */

                auto isAborted = makeAbortFlag(res);

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (!requireAdminKey(res, req, isAborted)) {
                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating */
                        }
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                /** get rid from the request body */
                                std::vector<std::string> rids = parsedJson["rid"].get<std::vector<std::string>>();

                                /** Prepare the response JSON array */
                                nlohmann::json data = nlohmann::json::array();

                                /** Iterate over each `rid` and collect responses */
                                for (const auto& rid : rids) {
                                    nlohmann::json roomData;
                                    roomData["rid"] = rid;

                                    {
                                        tbb::concurrent_hash_map<std::string,
                                                                 tbb::concurrent_hash_map<std::string, bool>>::accessor
                                            outer_accessor;

                                        if (ThreadSafe::topics.find(outer_accessor, rid)) {
                                            nlohmann::json uidArray = nlohmann::json::array();

                                            for (const auto& entry : outer_accessor->second) {
                                                uidArray.push_back(entry.first);
                                            }

                                            roomData["uid"] = uidArray;
                                        } else {
                                            roomData["uid"] = nlohmann::json::array();
                                        }
                                    }

                                    data.push_back(roomData);
                                }

                                replyJson(res, isAborted, "200 OK", data.dump());
                            } catch (const std::exception&) {
                                replyJson(res, isAborted, "400 Bad Request", R"({"message": "Invalid JSON format!"})");
                            }
                        }
                    });
                } catch (const std::exception&) {
                    replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                }
            })
        .get(
            "/api/v1/users/subscribe/room/:rid",
            [this](auto* res, auto* req) {
                /** shared_ptr (not a stack flag): the private-room verification path
                 *  completes ASYNCHRONOUSLY after this handler returns, so the abort
                 *  flag must outlive the handler frame. Read/written only on this
                 *  loop's thread (onAborted and the deferred completion both run here). */
                auto isAborted = std::make_shared<bool>(false);
                std::string rid = std::string(req->getParameter("rid"));
                std::string uid = std::string(req->getHeader("uid"));

                res->onAborted([isAborted]() {
                    *isAborted = true;
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                });

                try {
                    if (!requireClientKey(res, req, isAborted)) {
                        return;
                    }

                    /** per-user token (no-op while connection_token_secret is unset) */
                    if (!verifyConnectionToken(uid, req->getHeader("token"))) {
                        replyJson(res, isAborted, "401 Unauthorized", R"({"message": "Invalid or expired token!"})");

                        return;
                    }

                    worker_t* worker = nullptr;

                    {
                        /** the caller UID must have an active connection on this server.
                         *  Only the worker pointer is taken out of the accessor scope:
                         *  worker_t objects live for the process lifetime, whereas the raw
                         *  ws pointer could be freed the moment the accessor is released,
                         *  so ws is re-looked-up on the owner thread (runOnOwnerThread). */
                        tbb::concurrent_hash_map<std::string, WebSocketData>::const_accessor accessor;

                        if (!ThreadSafe::connections.find(accessor, uid)) {
                            replyJson(res, isAborted, "404 Not Found", R"({"message": "Invalid uid!"})");

                            return;
                        }

                        worker = accessor->second.worker;
                    }

                    if (rid.empty() || rid.size() > 160) {
                        replyJson(res, isAborted, "400 Bad Request",
                                  R"({"message": "The room ID length should be between 1 to 160 characters!"})");

                        return;
                    }

                    /** checking if the correct room type is received */
                    uint8_t roomType = parseRoomType(rid);
                    if (roomType == 255) {
                        replyJson(res, isAborted, "400 Bad Request",
                                  "{\"message\": \"The provided room type is invalid!\"}");

                        return;
                    }

                    {
                        /** reject if the user is already subscribed to this room */
                        tbb::concurrent_hash_map<std::string,
                                                 tbb::concurrent_hash_map<std::string, uint8_t>>::const_accessor
                            uid_to_rid_outer_accessor;

                        if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, uid)) {
                            auto& inner_map = uid_to_rid_outer_accessor->second;

                            tbb::concurrent_hash_map<std::string, uint8_t>::const_accessor inner_accessor;
                            if (inner_map.find(inner_accessor, rid)) {
                                replyJson(res, isAborted, "400 Bad Request",
                                          R"({"message": "You are already subscribed to the given room!"})");

                                return;
                            }
                        }
                    }

                    /** checking if the user is banned from the given room */
                    {
                        tbb::concurrent_hash_map<
                            std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor outer_accessor;

                        if (ThreadSafe::bannedConnections.find(outer_accessor, rid) &&
                            outer_accessor->second.count(uid)) {

                            replyJson(res, isAborted, "403 Forbidden",
                                      R"({"message": "You have been banned from this room!"})");

                            return;
                        }
                    }

                    if (roomType == static_cast<uint8_t>(Rooms::PRIVATE) ||
                        roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE) ||
                        roomType == static_cast<uint8_t>(Rooms::PRIVATE_CACHE) ||
                        roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)) {
                        if (getWebhookStatus(Webhooks::ON_VERIFICATION_REQUEST) == 1) {
                            std::ostringstream payload;

                            payload << "{\"event\":\"ON_VERIFICATION_REQUEST\", " << "\"uid\":\"" << jsonEscape(uid)
                                    << "\", " << "\"rid\":\"" << jsonEscape(rid) << "\"}";

                            std::string body = payload.str();

                            /** Note: the X-HMAC-Signature header is computed and added inside
                     *  the webhook sender using the configured webhookSecret, so no
                     *  signature needs to be built here.
                     *
                     *  The verification webhook is a BLOCKING HTTPS round-trip (up to two
                     *  3s connect attempts). It used to run right here on the event loop,
                     *  freezing every connection on this worker while the endpoint was
                     *  slow. Now it runs on a small bounded pool and completes back on
                     *  this loop via defer; `res` stays valid because onAborted is
                     *  registered and `isAborted` is only touched on this thread. */
                            std::string baseURL = UserData::getInstance().webHookBaseUrl;
                            std::string whPath = UserData::getInstance().webhookPath;
                            uWS::Loop* httpLoop = uWS::Loop::get();

                            bool queued = enqueueVerificationWebhook(
                                baseURL, whPath, body,
                                [httpLoop, res, isAborted, worker, uid, rid, roomType](int status) {
                                httpLoop->defer([status, res, isAborted, worker, uid, rid, roomType]() {
                                    if (*isAborted) {
                                        return; /** client went away while we verified */
                                    }

                                    if (status != 200) {
                                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                        res->cork([res]() {
                                            res->writeStatus("403 Forbidden");
                                            res->writeHeader("Content-Type", "application/json");
                                            res->end("{\"message\": \"You are not allowed to access this private "
                                                     "room!\"}");
                                        });
                                        return;
                                    }

                                    runOnOwnerThread(worker, uid,
                                                     [rid, roomType](SLWebSocket* aliveWs, worker_t* owner) {
                                                         openConnection(aliveWs, owner, rid, roomType);
                                                     });

                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(R"({"message": "Successfully subscribed to the given room!"})");
                                    });
                                });
                                });

                            if (!queued) {
                                /** verification pool saturated (endpoint slow/down) — shed
                     *  load instead of queueing unbounded latency */
                                replyJson(res, isAborted, "503 Service Unavailable",
                                          R"({"message": "Verification is temporarily unavailable!"})");
                            }

                            return; /** response completes asynchronously above */
                        } else {
                            replyJson(res, isAborted, "403 Forbidden",
                                      "{\"message\": \"The ON_VERIFICATION_REQUEST webhook must be enabled to " "activate private rooms!\"}");

                            return;
                        }
                    }

                    /** Run the subscribe on the socket's owner thread; the connection is
                     *  re-validated there, so a socket that closed since the check above
                     *  is simply skipped instead of being dereferenced after free. As a
                     *  bonus, openConnection now always runs on the owner thread, so the
                     *  SOMEONE_JOINED_THE_ROOM broadcast covers every worker (previously
                     *  the HTTP-handling worker was skipped). */
                    runOnOwnerThread(worker, uid, [rid, roomType](SLWebSocket* aliveWs, worker_t* owner) {
                        openConnection(aliveWs, owner, rid, roomType);
                    });

                    replyJson(res, isAborted, "200 OK", R"({"message": "Successfully subscribed to the given room!"})");
                } catch (const std::exception&) {
                    replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                }
            })
        .get("/api/v1/users/subscriptions/all",
             [this](auto* res, auto* req) {
                 /** get all the subscribed rooms from the given UIDs */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     std::string_view apiKey = req->getHeader("api-key");

                     if (!requireAdminKey(res, req, isAborted)) {
                         return;
                     }

                     /** Prepare the response JSON array */
                     nlohmann::json data = nlohmann::json::array();

                     /** EXCLUSIVE: iteration vs concurrent insert/erase (see registryIterationGuard) */
                     std::unique_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                     for (const auto& [uid, rids] : ThreadSafe::uidToRoomMapping) {
                         nlohmann::json roomData;
                         roomData["uid"] = uid;

                         std::vector<std::string> roomIDs;

                         for (const auto& [rid, _] : rids) {
                             roomIDs.push_back(rid);
                         }

                         roomData["rid"] = std::move(roomIDs);

                         data.push_back(std::move(roomData));
                     }

                     std::string response = data.dump();

                     replyJson(res, isAborted, "200 OK", response);
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .post("/api/v1/users/subscriptions",
              [this](auto* res, auto* req) {
                  /** get all the subscribed rooms from the given UIDs */

                  auto isAborted = makeAbortFlag(res);

                  try {
                      std::string_view apiKey = req->getHeader("api-key");

                      if (!requireAdminKey(res, req, isAborted)) {
                          return;
                      }

                      std::string body;

                      body.reserve(1024);

                      res->onData(
                          [res, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
                              if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating */
                        }
                        body.append(data.data(), data.length());

                              if (last) {
                                  try {
                                      nlohmann::json parsedJson = nlohmann::json::parse(body);

                                      /** get rid from the request body */
                                      std::vector<std::string> uids = parsedJson["uid"].get<std::vector<std::string>>();

                                      /** Prepare the response JSON array */
                                      nlohmann::json data = nlohmann::json::array();

                                      /** Iterate over each `rid` and collect responses */
                                      for (const auto& uid : uids) {
                                          nlohmann::json roomData;
                                          roomData["uid"] = uid;

                                          {
                                              tbb::concurrent_hash_map<
                                                  std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor
                                                  outer_accessor;

                                              if (ThreadSafe::uidToRoomMapping.find(outer_accessor, uid)) {
                                                  nlohmann::json ridArray = nlohmann::json::array();

                                                  for (const auto& entry : outer_accessor->second) {
                                                      ridArray.push_back(entry.first);
                                                  }

                                                  roomData["rid"] = ridArray;
                                              } else {
                                                  roomData["rid"] = nlohmann::json::array();
                                              }
                                          }

                                          data.push_back(roomData);
                                      }

                                      replyJson(res, isAborted, "200 OK", data.dump());
                                  } catch (const std::exception&) {
                                      replyJson(res, isAborted, "400 Bad Request",
                                                R"({"message": "Invalid JSON format!"})");
                                  }
                              }
                          });
                  } catch (const std::exception&) {
                      replyJson(res, isAborted, "500 Internal Server Error",
                                R"({"message": "Internal server error!"})");
                  }
              })
        .get("/api/v1/users/unsubscribe/room/:rid",
             [this](auto* res, auto* req) {
                 auto isAborted = std::make_shared<bool>(false);
                 std::string rid = std::string(req->getParameter("rid"));
                 std::string uid = std::string(req->getHeader("uid"));

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     if (!requireClientKey(res, req, isAborted)) {
                         return;
                     }

                     /** per-user token (no-op while connection_token_secret is unset) */
                     if (!verifyConnectionToken(uid, req->getHeader("token"))) {
                         replyJson(res, isAborted, "401 Unauthorized", R"({"message": "Invalid or expired token!"})");

                         return;
                     }

                     worker_t* worker = nullptr;

                     {
                         /** checking if there even is a connection with the provided UID.
                          *  Only the (process-lifetime) worker pointer leaves the accessor
                          *  scope; the ws itself is re-looked-up on its owner thread. */
                         tbb::concurrent_hash_map<std::string, WebSocketData>::const_accessor accessor;

                         if (!ThreadSafe::connections.find(accessor, uid)) {
                             replyJson(res, isAborted, "404 Not Found", R"({"message": "Invalid uid!"})");

                             return;
                         }

                         worker = accessor->second.worker;
                     }

                     /** checking if the room length is valid */
                     if (rid.empty() || rid.length() > 160) {
                         replyJson(res, isAborted, "400 Bad Request",
                                    R"({"message": "The room id length should be between 1 to 160 characters!"})");

                         return;
                     }

                     /** checking if the correct room type is received */
                     uint8_t roomType = parseRoomType(rid);
                     if (roomType == 255) {
                         replyJson(res, isAborted, "400 Bad Request",
                                   "{\"message\": \"The provided room type is invalid!\"}");

                         return;
                     }

                     /** checking if the user is already unsubscribed to the given room */
                     {
                         tbb::concurrent_hash_map<std::string,
                                                  tbb::concurrent_hash_map<std::string, uint8_t>>::const_accessor
                             uid_to_rid_outer_accessor;

                         if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, uid)) {
                             const auto& inner_map = uid_to_rid_outer_accessor->second;

                             /** Check if the room is already present under the UID */
                             tbb::concurrent_hash_map<std::string, uint8_t>::const_accessor inner_accessor;
                             if (!inner_map.find(inner_accessor, rid)) {

                                 replyJson(res, isAborted, "400 Bad Request",
                                           R"({"message": "You are not subscribed to the given room!"})");

                                 return;
                             }
                         } else {
                             replyJson(res, isAborted, "400 Bad Request",
                                       R"({"message": "You are not subscribed to the given room!"})");

                             return;
                         }
                     }

                     /** close the connection for the given rid on the socket's owner
                      *  thread; re-validated there so a just-closed socket is skipped
                      *  instead of dereferenced after free */
                     runOnOwnerThread(worker, uid, [rid, uid, roomType](SLWebSocket* aliveWs, worker_t* owner) {
                         closeConnection(aliveWs, owner, rid, uid, roomType);
                     });

                     replyJson(res, isAborted, "200 OK",
                               R"({"message": "Successfully unsubscribed from the given room!"})");
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .post(
            "/api/v1/broadcast",
            [this](auto* res, auto* req) {
                /** broadcast a message to everyone connected to the server */
                auto isAborted = makeAbortFlag(res);

                try {
                    if (!requireAdminKey(res, req, isAborted)) {
                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating */
                        }
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                std::string message = parsedJson["message"].get<std::string>();
                                std::string messageToBroadcast = "{\"data\":\"" + jsonEscape(message) +
                                                                 "\",\"source\":\"admin\",\"rid\":\"" + BROADCAST +
                                                                 "\"}";

                                /** broadcast a message to all the rooms */
                                std::for_each(::workers.begin(), ::workers.end(), [messageToBroadcast](worker_t& w) {
                                    /** Defer the message publishing to the worker's loop */
                                    w.loop_->defer([&w, messageToBroadcast]() {
                                        w.app_->publish(BROADCAST, messageToBroadcast, uWS::OpCode::TEXT, true);
                                    });
                                });

                                replyJson(res, isAborted, "200 OK",
                                           R"({"message": "Successfully broadcasted the message to everyone on the server!"})");
                            } catch (const std::exception&) {
                                replyJson(res, isAborted, "400 Bad Request", R"({"message": "Invalid JSON format!"})");
                            }
                        }
                    });
                } catch (const std::exception&) {
                    replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                }
            })
        .post(
            "/api/v1/rooms/broadcast",
            [this](auto* res, auto* req) {
                /** broadcast a message to a particular room */

                auto isAborted = makeAbortFlag(res);

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (!requireAdminKey(res, req, isAborted)) {
                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating */
                        }
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                std::string message = parsedJson["message"].get<std::string>();
                                std::vector<std::string> rids = parsedJson["rid"].get<std::vector<std::string>>();

                                for (const auto& rid : rids) {
                                    std::string messageToBroadcast = "{\"data\":\"" + jsonEscape(message) +
                                                                     "\",\"source\":\"admin\",\"rid\":\"" +
                                                                     jsonEscape(rid) + "\"}";

                                    /** broadcast a message to a specific room */
                                    std::for_each(
                                        ::workers.begin(), ::workers.end(), [messageToBroadcast, rid](worker_t& w) {
                                            /** Defer the message publishing to the worker's loop */
                                            w.loop_->defer([&w, messageToBroadcast, rid]() {
                                                w.app_->publish(rid, messageToBroadcast, uWS::OpCode::TEXT, true);
                                            });
                                        });
                                }

                                replyJson(res, isAborted, "200 OK",
                                           R"({"message": "Successfully broadcasted the message to the given rooms!"})");
                            } catch (const std::exception&) {
                                replyJson(res, isAborted, "400 Bad Request", R"({"message": "Invalid JSON format!"})");
                            }
                        }
                    });
                } catch (const std::exception&) {
                    replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                }
            })
        .post(
            "/api/v1/users/broadcast",
            [this](auto* res, auto* req) {
                /** broadcast a message to a particular connection */

                auto isAborted = makeAbortFlag(res);

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (!requireAdminKey(res, req, isAborted)) {
                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating */
                        }
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                std::string message = parsedJson["message"].get<std::string>();
                                std::vector<std::string> uids = parsedJson["uid"].get<std::vector<std::string>>();

                                for (const auto& uid : uids) {
                                    std::string messageToBroadcast = "{\"data\":\"" + jsonEscape(message) +
                                                                     "\",\"source\":\"admin\",\"rid\":\"" +
                                                                     jsonEscape(uid) + "\"}";

                                    /** broadcast a message to a specific member of a room */
                                    std::for_each(
                                        ::workers.begin(), ::workers.end(), [messageToBroadcast, uid](worker_t& w) {
                                            /** Defer the message publishing to the worker's loop */
                                            w.loop_->defer([&w, messageToBroadcast, uid]() {
                                                w.app_->publish(uid, messageToBroadcast, uWS::OpCode::TEXT, true);
                                            });
                                        });
                                }

                                replyJson(res, isAborted, "200 OK",
                                           R"({"message": "Successfully broadcasted the message to the given connections!"})");
                            } catch (const std::exception&) {
                                replyJson(res, isAborted, "400 Bad Request", R"({"message": "Invalid JSON format!"})");
                            }
                        }
                    });
                } catch (const std::exception&) {
                    replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                }
            })
        .post(
            "/api/v1/rooms/users/ban",
            [this](auto* res, auto* req) {
                /** ban all the users in a room and prevent them from connecting again (it will disconnect the user from the server) */

                auto isAborted = makeAbortFlag(res);

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (!requireAdminKey(res, req, isAborted)) {
                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating */
                        }
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                /** saving all the banned connections in a map */
                                for (const auto& item : parsedJson) {
                                    /** Extract `rid` and `uid` from each item in the request */
                                    std::string rid = item["rid"];
                                    std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                                    /** checking if the correct room type is received
                             *  ("global" is a valid ban target that has no room prefix) */
                                    uint8_t roomType = parseRoomType(rid);
                                    if (roomType == 255 && rid != "global") {
                                        replyJson(res, isAborted, "400 Bad Request",
                                                  "{\"message\": \"The provided room type is invalid!\"}");

                                        return;
                                    }

                                    /** Banning happens in two passes. Pass 1 records the bans
                                     *  while holding the bannedConnections accessor; pass 2
                                     *  disconnects AFTER that accessor is released. Disconnecting
                                     *  inline used to self-deadlock: closeConnection() erases
                                     *  bannedConnections[rid] when the banned user was the room's
                                     *  last member, and TBB accessors are not reentrant, so the
                                     *  thread blocked forever on the accessor it already held. */
                                    std::vector<std::string> newlyBanned;

                                    {
                                        /** structural mutation of an iterated registry map */
                                        std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                                        tbb::concurrent_hash_map<std::string,
                                                                 tbb::concurrent_hash_map<std::string, bool>>::accessor
                                            global_accessor;
                                        tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                                        /** Try to find or insert the outer map entry */
                                        if (!ThreadSafe::bannedConnections.find(global_accessor, rid)) {
                                            ThreadSafe::bannedConnections.insert(global_accessor, rid);
                                        }

                                        for (const auto& uid : uids) {
                                            /** Check if uid already exists before inserting */
                                            if (!global_accessor->second.find(user_accessor, uid)) {
                                                global_accessor->second.insert(user_accessor, uid);
                                                user_accessor->second = true;
                                                newlyBanned.push_back(uid);
                                            }
                                        }
                                    }

                                    /** Pass 2: disconnect each newly banned user on the thread
                                     *  that owns its socket (runOnOwnerThread re-validates the
                                     *  connection there, so no raw ws pointer crosses threads). */
                                    for (const auto& uid : newlyBanned) {
                                        worker_t* worker = nullptr;
                                        {
                                            tbb::concurrent_hash_map<std::string, WebSocketData>::const_accessor
                                                conn_accessor;
                                            if (ThreadSafe::connections.find(conn_accessor, uid)) {
                                                worker = conn_accessor->second.worker;
                                            }
                                        }

                                        if (!worker) {
                                            continue; /** banned uid has no live connection */
                                        }

                                        if (rid == "global") {
                                            runOnOwnerThread(worker, uid, [](SLWebSocket* aliveWs, worker_t*) {
                                                aliveWs->end(1008, "{\"data\":\"YOU_HAVE_BEEN_BANNED\", "
                                                                   "\"source\":\"admin\"}");
                                            });
                                        } else {
                                            runOnOwnerThread(
                                                worker, uid,
                                                [rid, uid, roomType](SLWebSocket* aliveWs, worker_t* owner) {
                                                    closeConnection(aliveWs, owner, rid, uid, roomType);

                                                    /** Tell the user in case of room ban */
                                                    aliveWs->send("{\"data\":\"YOU_HAVE_BEEN_BANNED\", "
                                                                  "\"source\":\"admin\", \"rid\":\"" +
                                                                      jsonEscape(rid) + "\"}",
                                                                  uWS::OpCode::TEXT, true);
                                                });
                                        }
                                    }
                                }

                                log(LogLevel::INFO, "Admin API: users banned via /api/v1/rooms/users/ban");

                                replyJson(res, isAborted, "200 OK",
                                           R"({"message": "Given users are successfully banned from the given rooms!"})");
                            } catch (const std::exception&) {
                                replyJson(res, isAborted, "400 Bad Request", R"({"message": "Invalid JSON format!"})");
                            }
                        }
                    });
                } catch (const std::exception&) {
                    replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                }
            })
        .post(
            "/api/v1/rooms/users/unban",
            [this](auto* res, auto* req) {
                /** ban all the users in a room and prevent them from connecting again (it will disconnect the user from the server) */

                auto isAborted = makeAbortFlag(res);

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (!requireAdminKey(res, req, isAborted)) {
                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating */
                        }
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                for (const auto& item : parsedJson) {
                                    /** Extract `rid` and `uid` from each item in the request */
                                    std::string rid = item["rid"];
                                    std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                                    {
                                        /** structural mutation of an iterated registry map */
                                        std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                                        tbb::concurrent_hash_map<std::string,
                                                                 tbb::concurrent_hash_map<std::string, bool>>::accessor
                                            global_accessor;
                                        tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                                        /** Check if the room exists before trying to erase */
                                        if (ThreadSafe::bannedConnections.find(global_accessor, rid)) {
                                            for (const auto& uid : uids) {
                                                /** Check if the user exists before erasing */
                                                if (global_accessor->second.find(user_accessor, uid)) {
                                                    global_accessor->second.erase(user_accessor);
                                                }
                                            }

                                            /** If the inner map becomes empty, erase the entire entry */
                                            if (global_accessor->second.empty()) {
                                                ThreadSafe::bannedConnections.erase(global_accessor);
                                            }
                                        }
                                    }
                                }

                                if (!*isAborted) {
                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(
                                            R"({"message": "Given users are successfully unbanned from the given rooms!"})");
                                        log(LogLevel::INFO, "Admin API: users unbanned via /api/v1/rooms/users/unban");
                                    });
                                }
                            } catch (const std::exception&) {
                                replyJson(res, isAborted, "400 Bad Request", R"({"message": "Invalid JSON format!"})");
                            }
                        }
                    });
                } catch (const std::exception&) {
                    replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                }
            })
        .put("/api/v1/server/messaging/:action",
             [this](auto* res, auto* req) {
                 /** enable or disable message sending at the server level (for everyone) */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     std::string_view apiKey = req->getHeader("api-key");
                     std::string_view action = req->getParameter("action");

                     if (!requireAdminKey(res, req, isAborted)) {
                         return;
                     }

                     if (action == "enable") {
                         isMessagingDisabled.store(false, std::memory_order_relaxed);
                     } else if (action == "disable") {
                         isMessagingDisabled.store(true, std::memory_order_relaxed);
                     } else {
                         replyJson(res, isAborted, "400 Bad Request", R"({"message": "Invalid action!"})");
                         return;
                     }

                     log(LogLevel::INFO, "Admin API: server-wide messaging ", action, "d");

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res, action]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");

                             if (action == "enable")
                                 res->end(R"({"message": "Messaging successfully enabled for everyone!"})");
                             else
                                 res->end(R"({"message": "Messaging successfully disabled for everyone!"})");
                         });
                     }
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .post(
            "/api/v1/rooms/messaging/:action",
            [this](auto* res, auto* req) {
                /** enable or disable messaging at room level */

                auto isAborted = makeAbortFlag(res);

                try {
                    std::string_view apiKey = req->getHeader("api-key");
                    /** COPY, not a view: `action` is read inside the onData callback, which
                     *  runs after this handler returns and the HttpRequest is destroyed —
                     *  a dangling view here decided enable-vs-disable. */
                    std::string action(req->getParameter("action"));

                    if (!requireAdminKey(res, req, isAborted)) {
                        return;
                    }

                    /** reject an unknown action up front rather than mid-loop, where an
                     *  empty body would skip validation entirely and still report success */
                    if (action != "enable" && action != "disable") {
                        replyJson(res, isAborted, "400 Bad Request", R"({"message": "Invalid action!"})");
                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, body = std::move(body), action, isAborted](std::string_view data,
                                                                                bool last) mutable {
                        if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating (see MAX_REQUEST_BODY_BYTES) */
                        }
                        if (body.size() + data.size() > MAX_REQUEST_BODY_BYTES) {
                            return; /** oversized body: stop accumulating */
                        }
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                for (const auto& item : parsedJson) {
                                    /** Extract `rid` and `uid` from each item in the request */
                                    std::string rid = item["rid"];
                                    std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                                    if (action == "enable") {
                                        {
                                            /** structural mutation of an iterated registry map */
                                            std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                                            tbb::concurrent_hash_map<
                                                std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor
                                                global_accessor;
                                            tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                                            /** Check if the room exists before trying to erase */
                                            if (ThreadSafe::disabledConnections.find(global_accessor, rid)) {
                                                for (const auto& uid : uids) {
                                                    /** Check if the user exists before erasing */
                                                    if (global_accessor->second.find(user_accessor, uid)) {
                                                        global_accessor->second.erase(user_accessor);
                                                    }
                                                }

                                                /** If the inner map becomes empty, erase the entire entry */
                                                if (global_accessor->second.empty()) {
                                                    ThreadSafe::disabledConnections.erase(global_accessor);
                                                }
                                            }
                                        }
                                    } else if (action == "disable") {
                                        {
                                            /** structural mutation of an iterated registry map */
                                            std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                                            tbb::concurrent_hash_map<
                                                std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor
                                                global_accessor;
                                            tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                                            /** Try to find or insert the outer map entry */
                                            if (!ThreadSafe::disabledConnections.find(global_accessor, rid)) {
                                                ThreadSafe::disabledConnections.insert(global_accessor, rid);
                                            }

                                            for (const auto& uid : uids) {
                                                /** Check if uid already exists before inserting */
                                                if (!global_accessor->second.find(user_accessor, uid)) {
                                                    global_accessor->second.insert(user_accessor, uid);
                                                    user_accessor->second = true;
                                                }
                                            }
                                        }
                                    } else {
                                        replyJson(res, isAborted, "400 Bad Request",
                                                  R"({"message": "Invalid action!"})");

                                        return;
                                    }
                                }

                                log(LogLevel::INFO, "Admin API: per-room messaging ", action, "d for given users");

                                if (!*isAborted) {
                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res, action]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");

                                        if (action == "enable")
                                            res->end(
                                                R"({"message": "Messaging successfully enabled for the given members in the given rooms!"})");
                                        else
                                            res->end(
                                                R"({"message": "Messaging successfully disabled for the given members in the given rooms!"})");
                                    });
                                }
                            } catch (const std::exception&) {
                                replyJson(res, isAborted, "400 Bad Request", R"({"message": "Invalid JSON format!"})");
                            }
                        }
                    });
                } catch (const std::exception&) {
                    replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                }
            })
        .get("/api/v1/users/banned",
             [this](auto* res, auto* req) {
                 /** Handle the request to fetch all banned connections */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     std::string_view apiKey = req->getHeader("api-key");

                     if (!requireAdminKey(res, req, isAborted)) {
                         return;
                     }

                     nlohmann::json data = nlohmann::json::array();

                     /** EXCLUSIVE: iteration vs concurrent insert/erase (see registryIterationGuard) */
                     std::unique_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                     for (const auto& [rid, users] : ThreadSafe::bannedConnections) {
                         nlohmann::json roomData;
                         roomData["rid"] = rid;

                         std::vector<std::string> userKeys;

                         for (const auto& [uid, _] : users) {
                             userKeys.push_back(uid);
                         }

                         roomData["uid"] = std::move(userKeys);

                         data.push_back(std::move(roomData));
                     }

                     replyJson(res, isAborted, "200 OK", data.dump());
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .get("/api/v1/users/messaging/disabled",
             [this](auto* res, auto* req) {
                 /** Handle the request to fetch all disabled connections */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     std::string_view apiKey = req->getHeader("api-key");

                     if (!requireAdminKey(res, req, isAborted)) {
                         return;
                     }

                     nlohmann::json json_response = nlohmann::json::array();

                     /** EXCLUSIVE: iteration vs concurrent insert/erase (see registryIterationGuard) */
                     std::unique_lock<std::shared_mutex> iterGuard(registryIterationGuard);
                     for (const auto& [rid, users] : ThreadSafe::disabledConnections) {
                         nlohmann::json roomData;
                         roomData["rid"] = rid;

                         std::vector<std::string> userKeys;

                         for (const auto& [uid, _] : users) {
                             userKeys.push_back(uid);
                         }

                         roomData["uid"] = std::move(userKeys);

                         json_response.push_back(std::move(roomData));
                     }

                     replyJson(res, isAborted, "200 OK", json_response.dump());
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .get("/api/v1/messages/room/:rid",
             [this](auto* res, auto* req) {
                 /** retrieve the messages for cache rooms (for other rooms no data will be returned) */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     std::string_view rid = req->getParameter("rid");
                     std::string_view apiKey = req->getHeader("api-key");
                     std::string_view uid = req->getHeader("uid");

                     /** API key FIRST: the membership checks below return distinguishable
                      *  errors, so running them pre-auth let unauthenticated callers probe
                      *  which rooms exist and who is in them. */
                     if (!requireClientKey(res, req, isAborted)) {
                         return;
                     }

                     /** per-user token (no-op while connection_token_secret is unset) */
                     if (!verifyConnectionToken(std::string(uid), req->getHeader("token"))) {
                         replyJson(res, isAborted, "401 Unauthorized", R"({"message": "Invalid or expired token!"})");

                         return;
                     }

                     {
                         tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor
                             outer_accessor;

                         if (!ThreadSafe::topics.find(outer_accessor, std::string(rid))) {
                             replyJson(res, isAborted, "403 Forbidden", R"({"message": "Access denied!"})");

                             return;
                         } else {
                             /** Access the inner map corresponding to 'rid' */
                             tbb::concurrent_hash_map<std::string, bool>& inner_map = outer_accessor->second;

                             /** Create an accessor for the inner map */
                             tbb::concurrent_hash_map<std::string, bool>::accessor inner_accessor;

                             /** Check if value exists in the inner map (uid) */
                             if (!inner_map.find(inner_accessor, std::string(uid))) {
                                 replyJson(res, isAborted, "403 Forbidden", R"({"message": "Access denied!"})");

                                 return;
                             }
                         }
                     }

                     /** Cache-room messages sit in PER-WORKER thread-local LMDB write
                      *  batches, so flushing on this thread alone (the old behavior) missed
                      *  everything buffered by the other workers and returned stale data.
                      *  Fan a flush out to every worker loop and only read + respond once
                      *  the last one has committed. `rid` is copied out of the request
                      *  (string_views into req die when this handler returns). */
                     auto pending = std::make_shared<std::atomic<size_t>>(::workers.size());
                     uWS::Loop* httpLoop = uWS::Loop::get();
                     std::string ridStr(rid);

                     for (auto& w : ::workers) {
                         w.loop_->defer([pending, httpLoop, res, isAborted, ridStr]() {
                             /** flushes THIS worker's thread-local batch */
                             write_worker(ridStr, "", true);

                             if (pending->fetch_sub(1, std::memory_order_acq_rel) == 1) {
                                 /** last flush done — respond on the thread that owns `res`
                  *  (isAborted is only read there, same thread as onAborted) */
                                 httpLoop->defer([res, isAborted, ridStr]() {
                                     replyJson(res, isAborted, "200 OK", read_worker(ridStr));
                                 });
                             }
                         });
                     }
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .del("/api/v1/database",
             [this](auto* res, auto* req) {
                 /** delete all the data present in the LMDB database */

                 auto isAborted = makeAbortFlag(res);

                 try {
                     std::string_view apiKey = req->getHeader("api-key");

                     if (!requireAdminKey(res, req, isAborted)) {
                         return;
                     }

                     MDB_txn* txn = nullptr;

                     try {
                         if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
                             throw std::runtime_error("Failed to begin transaction.");
                         }

                         /** drop all keys but keep the database structure (0 = truncate).
                          *  Null the handle after abort/commit: both FREE the txn, and the
                          *  catch below aborts it again — a double free. */
                         if (mdb_drop(txn, g_dbi, 0) != 0) {
                             mdb_txn_abort(txn);
                             txn = nullptr;
                             throw std::runtime_error("Failed to drop database.");
                         }

                         int commitRc = mdb_txn_commit(txn);
                         txn = nullptr; /** freed by mdb_txn_commit, success or not */
                         if (commitRc != 0) {
                             throw std::runtime_error("Failed to commit transaction.");
                         }

                         log(LogLevel::WARN, "Admin API: LMDB message store TRUNCATED via DELETE /api/v1/database");

                         replyJson(res, isAborted, "200 OK", R"({"message": "Database truncated successfully!"})");
                     } catch (const std::exception& e) {
                         /** abort the transaction so it doesn't leak on the error path */
                         if (txn)
                             mdb_txn_abort(txn);

                         replyJson(res, isAborted, "500 Internal Server Error",
                                   R"({"message": "Internal server error!"})");
                     }
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .get("/api/v1/ping",
             [](auto* res, auto* /*req*/) {
                 auto isAborted = makeAbortFlag(res);

                 try {
                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("200 OK");
                             res->end("pong!");
                         });
                     }
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .any("/*",
             [](auto* res, auto* /*req*/) {
                 auto isAborted = makeAbortFlag(res);

                 try {
                     replyJson(res, isAborted, "404 Not Found",
                               R"({"message": "The requested resource is not found!"})");
                 } catch (const std::exception&) {
                     replyJson(res, isAborted, "500 Internal Server Error", R"({"message": "Internal server error!"})");
                 }
             })
        .listen(listenPort, [this, listenPort](auto* token) {
            listen_socket_ = token;
            if (listen_socket_) {
                log(LogLevel::INFO, "Thread ", std::this_thread::get_id(), " listening on port ", listenPort);
            } else {
                log(LogLevel::ERROR, "Thread ", std::this_thread::get_id(), " failed to listen on port ", listenPort);
            }
        });

    app_->run();

    stopWebhookIoContext();

    log(LogLevel::INFO, "Thread ", std::this_thread::get_id(), " exiting");
}
