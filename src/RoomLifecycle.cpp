#include "RoomLifecycle.h"

#include <algorithm>
#include <shared_mutex>
#include <string>
#include <string_view>

#include "Config.h"
#include "LmdbStore.h"
#include "Logging.h"
#include "Util.h"
#include "Webhooks.h"

namespace {
    /**
     * Webhook body for a room lifecycle event, appended into ONE reserved string.
     *
     * The previous std::ostringstream + jsonEscape() chain paid for a locale,
     * virtual stream dispatch and a fresh heap string per escaped field — on a path
     * that runs once per (socket, room) for every socket in a disconnect storm, with
     * webhooks producing 100k+ events per run. Same technique as the per-message
     * envelope on the hot path. connections_in_room stays a JSON STRING (as before)
     * so existing consumers keep parsing it; -1 is still emitted for "room was not
     * in topics" exactly as it was.
     */
    std::string roomEventPayload(
        const char* event, std::string_view uid, std::string_view rid, bool withCount, int connectionsInRoom) {
        std::string body;
        body.reserve(96 + uid.size() + rid.size());
        body += "{\"event\":\"";
        body += event;
        body += "\", \"uid\":\"";
        appendJsonEscaped(body, uid);
        body += "\", \"rid\":\"";
        appendJsonEscaped(body, rid);
        if (withCount) {
            body += "\", \"connections_in_room\":\"";
            body += std::to_string(connectionsInRoom);
        }
        body += "\"}";
        return body;
    }

    /** SOMEONE_JOINED/LEFT_THE_ROOM presence broadcast for state rooms. */
    std::string presencePayload(const char* data, std::string_view metadata, std::string_view rid) {
        std::string body;
        body.reserve(80 + metadata.size() + rid.size());
        body += "{\"data\":\"";
        body += data;
        body += "\", \"metadata\":\"";
        appendJsonEscaped(body, metadata);
        body += "\", \"source\":\"server\", \"rid\":\"";
        appendJsonEscaped(body, rid);
        body += "\"}";
        return body;
    }
} // namespace

/** unsubscribe from the current room and do some cleanup */
void closeConnection(
    SLWebSocket* ws, worker_t* worker, std::string rid, std::string uid, uint8_t roomType, bool isClosed) {
    PerSocketData* ud = ws->getUserData();

    if (isClosed == false) {
        /** drop the socket-local subscription (owner thread; the hot path reads this)
         *  and this worker's claim on the room's publish mask */
        ud->rooms.erase(rid);
        roomWorkersRemove(rid, workerIndex(worker));

        /** structural mutation of iterated registry maps: shared iteration guard */
        std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);

        /** remove the RID from the uid -> room mapping (global cross-thread view) */
        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor
            uid_to_rid_outer_accessor;
        if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, ud->uid)) {
            auto& inner_uid_to_rid_map = uid_to_rid_outer_accessor->second;

            /** erase by key: one locked lookup instead of find + erase(accessor) */
            inner_uid_to_rid_map.erase(rid);

            if (inner_uid_to_rid_map.empty()) {
                /** the uid now has no rooms: mark it orphaned (true) */
                tbb::concurrent_hash_map<std::string, bool>::accessor uid_outer_accessor;
                if (ThreadSafe::uid.find(uid_outer_accessor, ud->uid)) {
                    if (!uid_outer_accessor->second) {
                        uid_outer_accessor->second = true;
                    }
                }

                ThreadSafe::uidToRoomMapping.erase(uid_to_rid_outer_accessor);
            }
        }
    }

    /** -1 = the room was not in `topics` at all, which is NOT the same as "the
     *  room is now empty". Using 0 for both made a missing room wipe the cache
     *  entry and fire ON_ROOM_VACATED for a room that may still have members. */
    int size = -1;

    /** remove the user from the room in topics (mutation: shared iteration guard,
     *  scoped so it is NOT held across the defers/webhooks below) */
    {
        std::shared_lock<std::shared_mutex> topicsIterGuard(registryIterationGuard);
        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor outer_accessor;

        if (ThreadSafe::topics.find(outer_accessor, rid)) {
            auto& inner_map = outer_accessor->second;
            inner_map.erase(ud->uid); /* one locked lookup, not find + erase(accessor) */
            size = static_cast<int>(inner_map.size());

            /** room empty: drop it along with its disabled/banned entries */
            if (size == 0) {
                ThreadSafe::topics.erase(outer_accessor);
                ThreadSafe::disabledConnections.erase(rid);
                ThreadSafe::bannedConnections.erase(rid);
            }
        }
    }

    log(LogLevel::DEBUG, "Unsubscribed: uid=", uid, " rid=", rid, " (room size ", size, ")");

    /** Unsubscribe on the correct thread. Off-thread we must NOT capture the raw
     *  ws pointer (it may be freed before the deferred lambda runs) — re-look-up
     *  by uid on the owner thread instead. */
    if (worker->thread_->get_id() != std::this_thread::get_id()) {
        runOnOwnerThread(worker, uid, [rid](SLWebSocket* aliveWs, worker_t*) { aliveWs->unsubscribe(rid); });
    } else {
        ws->unsubscribe(rid);
    }

    /** A vacated cache room: schedule its history for deletion at this thread's
     *  next LMDB flush. Deferred on purpose — the old synchronous delete committed
     *  (and msync'd) once per vacated room, on the event loop, in the middle of a
     *  disconnect storm. */
    if (size == 0 && isCacheRoom(roomType)) {
        delete_worker(rid);
    }

    /** Broadcast disconnect message */
    if (isStateRoom(roomType)) {
        std::string result = presencePayload("SOMEONE_LEFT_THE_ROOM", ud->metadata, rid);

        /** Publish only to workers that still hold a subscriber of this room —
         *  same rule the per-message path uses, so a leave in a small room does
         *  not wake every loop on the box. (The leaver is already removed, so
         *  the mask is exactly the remaining audience.) */
        uint64_t mask = roomWorkerMaskFor(rid);
        const bool maskUsable = ::workers.size() <= MAX_MASKED_WORKERS;
        for (size_t wi = 0; wi < ::workers.size(); ++wi) {
            if (maskUsable && !(mask & (1ULL << wi))) {
                continue;
            }
            worker_t& w = ::workers[wi];
            w.loop_->defer([&w, rid, result]() { w.app_->publish(rid, result, uWS::OpCode::TEXT, true); });
        }
    }

    if (getWebhookStatus(Webhooks::ON_UNSUBSCRIBE) == 1) {
        std::string body = roomEventPayload("ON_UNSUBSCRIBE", ud->uid, rid, true, size);
        sendHTTPSPOSTRequestFireAndForget(
            UserData::getInstance().webHookBaseUrl, UserData::getInstance().webhookPath, body, {});
    }

    /** room vacate webhooks */
    if (size == 0 && getWebhookStatus(Webhooks::ON_ROOM_VACATED) == 1) {
        std::string body = roomEventPayload("ON_ROOM_VACATED", ud->uid, rid, false, 0);
        sendHTTPSPOSTRequestFireAndForget(
            UserData::getInstance().webHookBaseUrl, UserData::getInstance().webhookPath, body, {});
    }
}

/** subscribe to a new room */
void openConnection(SLWebSocket* ws, worker_t* worker, std::string rid, uint8_t roomType) {
    if (!rid.empty()) {
        PerSocketData* ud = ws->getUserData();
        const auto& uid = ud->uid;
        auto currentThreadId = std::this_thread::get_id();
        auto workerThreadId = worker->thread_->get_id();

        /** subscribe on the thread that owns the ws instance (off-thread: re-look-up
         *  by uid on the owner loop instead of capturing the raw ws pointer) */
        if (workerThreadId == currentThreadId) {
            ws->subscribe(rid);
        } else {
            runOnOwnerThread(worker, uid, [rid](SLWebSocket* aliveWs, worker_t*) { aliveWs->subscribe(rid); });
        }

        int size = 0;

        {
            /** structural mutation of an iterated registry map: shared iteration guard */
            std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
            tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor topicsAccessor;

            /** Single insert covers both cases: it creates the room entry if absent
             *  and otherwise hands back the existing one. The old find-then-insert
             *  pair was not atomic — if another thread created the room in between,
             *  insert() returned false, the locally built inner map (holding THIS
             *  uid) was discarded, and the subscriber went missing from `topics`
             *  while `size` was reported as 1. */
            ThreadSafe::topics.insert(topicsAccessor, rid);
            auto& innerMap = topicsAccessor->second;

            tbb::concurrent_hash_map<std::string, bool>::accessor innerAccessor;
            if (innerMap.insert(innerAccessor, uid)) {
                innerAccessor->second = true;
            }

            size = static_cast<int>(innerMap.size());
        }

        log(LogLevel::DEBUG, "Subscribed: uid=", uid, " rid=", rid, " (room size ", size, ")");

        /** record the subscription socket-locally (owner thread; the hot path reads
         *  this) together with the room's shared worker mask, so publishing needs
         *  no map lookup at all */
        {
            RoomSub sub;
            sub.roomType = roomType;
            sub.workers = roomWorkersAdd(rid, workerIndex(worker));
            ud->rooms[rid] = std::move(sub);
        }

        {
            /** structural mutation of iterated registry maps: shared iteration guard */
            std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
            tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor
                uid_to_rid_outer_accessor;

            /** Single insert creates the uid's entry or hands back the existing one —
             *  one lookup, and the same shape as the `topics` fix above. The old
             *  find-then-insert did two lookups for a new uid, and had insert() ever
             *  lost a race its body was skipped and the rid silently dropped. */
            const bool createdUid = ThreadSafe::uidToRoomMapping.insert(uid_to_rid_outer_accessor, uid);
            auto& innerMap = uid_to_rid_outer_accessor->second;

            tbb::concurrent_hash_map<std::string, uint8_t>::accessor uid_to_rid_inner_accessor;
            if (innerMap.insert(uid_to_rid_inner_accessor, rid)) {
                uid_to_rid_inner_accessor->second = roomType;
            }

            if (createdUid) {
                /** uid now has a room: clear its orphaned flag (false) */
                tbb::concurrent_hash_map<std::string, bool>::accessor uid_outer_accessor;
                if (ThreadSafe::uid.find(uid_outer_accessor, uid)) {
                    if (uid_outer_accessor->second) {
                        uid_outer_accessor->second = false;
                    }
                }
            }
        }

        /** Broadcast the message to others if the room is a state room */
        if (isStateRoom(roomType)) {
            std::string broadcastMessage = presencePayload("SOMEONE_JOINED_THE_ROOM", ud->metadata, rid);

            /** openConnection always runs on the socket's owner thread (REST and
             *  ban callers arrive via runOnOwnerThread), so publish locally here
             *  and defer only to the OTHER workers that hold subscribers. */
            ws->publish(rid, broadcastMessage, uWS::OpCode::TEXT, true);

            const size_t selfIdx = workerIndex(worker);
            uint64_t mask = roomWorkerMaskFor(rid);
            const bool maskUsable = ::workers.size() <= MAX_MASKED_WORKERS;
            for (size_t wi = 0; wi < ::workers.size(); ++wi) {
                if (wi == selfIdx) {
                    continue;
                }
                if (maskUsable && !(mask & (1ULL << wi))) {
                    continue;
                }
                worker_t& w = ::workers[wi];
                w.loop_->defer(
                    [&w, broadcastMessage, rid]() { w.app_->publish(rid, broadcastMessage, uWS::OpCode::TEXT, true); });
            }
        }

        /** fire connection open webhook */
        if (getWebhookStatus(Webhooks::ON_SUBSCRIBE) == 1) {
            std::string body = roomEventPayload("ON_SUBSCRIBE", uid, rid, true, size);
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl, UserData::getInstance().webhookPath, body, {});
        }

        /** Room occupied webhooks */
        if (size == 1 && getWebhookStatus(Webhooks::ON_ROOM_OCCUPIED) == 1) {
            std::string body = roomEventPayload("ON_ROOM_OCCUPIED", uid, rid, false, 0);
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl, UserData::getInstance().webhookPath, body, {});
        }
    }
}
