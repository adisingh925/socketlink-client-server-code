#include "RoomLifecycle.h"

#include <algorithm>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <unordered_set>

#include "Config.h"
#include "LmdbStore.h"
#include "Logging.h"
#include "Util.h"
#include "Webhooks.h"

/** unsubscribe from the current room and do some cleanup */
void closeConnection(SLWebSocket* ws, worker_t* worker, std::string rid, std::string uid, uint8_t roomType,
                     bool isClosed) {
    if (isClosed == false) {
        /** drop the socket-local subscription (owner thread; the hot path reads this)
         *  and this worker's claim on the room's publish mask */
        ws->getUserData()->rooms.erase(rid);
        roomWorkersRemove(rid, workerIndex(worker));

        /** structural mutation of iterated registry maps: shared iteration guard */
        std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);

        /** remove the RID from the uid -> room mapping (global cross-thread view) */
        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor
            uid_to_rid_outer_accessor;
        if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, ws->getUserData()->uid)) {
            auto& inner_uid_to_rid_map = uid_to_rid_outer_accessor->second;

            {
                tbb::concurrent_hash_map<std::string, uint8_t>::accessor uid_to_rid_inner_accessor;
                if (inner_uid_to_rid_map.find(uid_to_rid_inner_accessor, rid)) {
                    inner_uid_to_rid_map.erase(uid_to_rid_inner_accessor);
                }
            }

            if (inner_uid_to_rid_map.empty()) {

                /** the uid now has no rooms: mark it orphaned (true) */
                tbb::concurrent_hash_map<std::string, bool>::accessor uid_outer_accessor;
                if (ThreadSafe::uid.find(uid_outer_accessor, ws->getUserData()->uid)) {
                    if (!uid_outer_accessor->second) {
                        uid_outer_accessor->second = true;
                    }
                }

                ThreadSafe::uidToRoomMapping.erase(uid_to_rid_outer_accessor);
            }
        }
    }

    int size = 0;

    /** remove the user from the room in topics (mutation: shared iteration guard,
     *  scoped so it is NOT held across the defers/webhooks below) */
    {
    std::shared_lock<std::shared_mutex> topicsIterGuard(registryIterationGuard);
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor outer_accessor;

    if (ThreadSafe::topics.find(outer_accessor, rid)) {
        auto& inner_map = outer_accessor->second;

        {
            tbb::concurrent_hash_map<std::string, bool>::accessor inner_accessor;
            if (inner_map.find(inner_accessor, ws->getUserData()->uid)) {
                inner_map.erase(inner_accessor);
            }
        }

        size = inner_map.size();

        /** room empty: drop it along with its disabled/banned entries */
        if (size == 0) {
            ThreadSafe::topics.erase(outer_accessor);

            for (auto& map : {&ThreadSafe::disabledConnections, &ThreadSafe::bannedConnections}) {
                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor
                    map_accessor;

                if (map->find(map_accessor, rid)) {
                    map->erase(map_accessor);
                }
            }
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

    static const std::unordered_set<uint8_t> validCacheRoomTypes = {
        static_cast<uint8_t>(Rooms::PUBLIC_CACHE), static_cast<uint8_t>(Rooms::PRIVATE_CACHE),
        static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE), static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)};

    /** delete the key value pair if it's a cache room */
    if (size == 0 && validCacheRoomTypes.count(roomType)) {
        delete_worker(rid);
    }

    /** Broadcast disconnect message */
    static const std::unordered_set<uint8_t> validRoomTypes = {
        static_cast<uint8_t>(Rooms::PUBLIC_STATE), static_cast<uint8_t>(Rooms::PRIVATE_STATE),
        static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE), static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)};

    if (validRoomTypes.count(roomType)) {
        std::string result = "{\"data\":\"SOMEONE_LEFT_THE_ROOM\", \"metadata\":\"" +
                             jsonEscape(ws->getUserData()->metadata) + "\", \"source\":\"server\", \"rid\":\"" +
                             jsonEscape(rid) + "\"}";

        /** Publish message to all workers */
        for (auto& w : ::workers) {
            w.loop_->defer([&w, rid, result]() { w.app_->publish(rid, result, uWS::OpCode::TEXT, true); });
        }
    }

    if (getWebhookStatus(Webhooks::ON_UNSUBSCRIBE) == 1) {
        std::ostringstream payload;
        payload << "{\"event\":\"ON_UNSUBSCRIBE\", " << "\"uid\":\"" << jsonEscape(ws->getUserData()->uid) << "\", "
                << "\"rid\":\"" << jsonEscape(rid) << "\", " << "\"connections_in_room\":\"" << size << "\"}";

        std::string body = payload.str();

        sendHTTPSPOSTRequestFireAndForget(UserData::getInstance().webHookBaseUrl, UserData::getInstance().webhookPath,
                                          body, {});
    }

    /** room vacate webhooks */
    if (size == 0) {
        if (getWebhookStatus(Webhooks::ON_ROOM_VACATED) == 1) {
            std::ostringstream payload;
            payload << "{\"event\":\"ON_ROOM_VACATED\", " << "\"uid\":\"" << jsonEscape(ws->getUserData()->uid)
                    << "\", " << "\"rid\":\"" << jsonEscape(rid) << "\"}";

            std::string body = payload.str();

            sendHTTPSPOSTRequestFireAndForget(UserData::getInstance().webHookBaseUrl,
                                              UserData::getInstance().webhookPath, body, {});
        }
    }
}

/** subscribe to a new room */
void openConnection(SLWebSocket* ws, worker_t* worker, std::string rid, uint8_t roomType) {
    if (!rid.empty()) {
        const auto& uid = ws->getUserData()->uid;
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

            if (ThreadSafe::topics.find(topicsAccessor, rid)) {
                auto& innerMap = topicsAccessor->second;

                tbb::concurrent_hash_map<std::string, bool>::accessor innerAccessor;

                if (innerMap.insert(innerAccessor, uid)) {
                    innerAccessor->second = true;
                }

                size = innerMap.size();
            } else {
                tbb::concurrent_hash_map<std::string, bool> newInnerMap;
                newInnerMap.emplace(uid, true);

                if (ThreadSafe::topics.insert(topicsAccessor, rid)) {
                    topicsAccessor->second = std::move(newInnerMap);
                }

                size = 1;
            }
        }

        log(LogLevel::DEBUG, "Subscribed: uid=", uid, " rid=", rid, " (room size ", size, ")");

        /** record the subscription socket-locally (owner thread; the hot path reads
         *  this) together with the room's shared worker mask, so publishing needs
         *  no map lookup at all */
        {
            RoomSub sub;
            sub.roomType = roomType;
            sub.workers = roomWorkersAdd(rid, workerIndex(worker));
            ws->getUserData()->rooms[rid] = std::move(sub);
        }

        {
            /** structural mutation of iterated registry maps: shared iteration guard */
            std::shared_lock<std::shared_mutex> iterGuard(registryIterationGuard);
            tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor
                uid_to_rid_outer_accessor;

            if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, uid)) {
                auto& innerMap = uid_to_rid_outer_accessor->second;

                tbb::concurrent_hash_map<std::string, uint8_t>::accessor uid_to_rid_inner_accessor;

                if (innerMap.insert(uid_to_rid_inner_accessor, rid)) {
                    uid_to_rid_inner_accessor->second = roomType;
                }
            } else {
                if (ThreadSafe::uidToRoomMapping.insert(uid_to_rid_outer_accessor, uid)) {
                    tbb::concurrent_hash_map<std::string, uint8_t>& innerMap = uid_to_rid_outer_accessor->second;

                    tbb::concurrent_hash_map<std::string, uint8_t>::accessor uid_to_rid_inner_accessor;
                    if (innerMap.insert(uid_to_rid_inner_accessor, rid)) {
                        uid_to_rid_inner_accessor->second = roomType;
                    }
                }

                /** uid now has a room: clear its orphaned flag (false) */
                tbb::concurrent_hash_map<std::string, bool>::accessor uid_outer_accessor;
                if (ThreadSafe::uid.find(uid_outer_accessor, uid)) {
                    if (uid_outer_accessor->second) {
                        uid_outer_accessor->second = false;
                    }
                }
            }
        }

        /** Broadcast the message to others if the room is public/private */
        if (roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE) ||
            roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE) ||
            roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) ||
            roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)) {
            std::string broadcastMessage = "{\"data\":\"SOMEONE_JOINED_THE_ROOM\", \"metadata\":\"" +
                                           jsonEscape(ws->getUserData()->metadata) +
                                           "\", \"source\":\"server\", \"rid\":\"" + jsonEscape(rid) + "\"}";

            if (workerThreadId == currentThreadId) {
                ws->publish(rid, broadcastMessage, uWS::OpCode::TEXT, true);
            }

            std::for_each(::workers.begin(), ::workers.end(), [broadcastMessage, rid](worker_t& w) {
                /** Check if the current thread ID matches the worker's thread ID */
                if (std::this_thread::get_id() != w.thread_->get_id()) {
                    /** Defer the message publishing to the worker's loop */
                    w.loop_->defer([&w, broadcastMessage, rid]() {
                        w.app_->publish(rid, broadcastMessage, uWS::OpCode::TEXT, true);
                    });
                }
            });
        }

        /** fire connection open webhook */
        if (getWebhookStatus(Webhooks::ON_SUBSCRIBE) == 1) {
            std::ostringstream payload;
            payload << "{\"event\":\"ON_SUBSCRIBE\", " << "\"uid\":\"" << jsonEscape(ws->getUserData()->uid) << "\", "
                    << "\"rid\":\"" << jsonEscape(rid) << "\", " << "\"connections_in_room\":\"" << size << "\"}";

            std::string body = payload.str();

            sendHTTPSPOSTRequestFireAndForget(UserData::getInstance().webHookBaseUrl,
                                              UserData::getInstance().webhookPath, body, {});
        }

        /** Room ocuupied webhooks */
        if (size == 1) {
            if (getWebhookStatus(Webhooks::ON_ROOM_OCCUPIED) == 1) {
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_OCCUPIED\", " << "\"uid\":\"" << jsonEscape(ws->getUserData()->uid)
                        << "\", " << "\"rid\":\"" << jsonEscape(rid) << "\"}";

                std::string body = payload.str();

                sendHTTPSPOSTRequestFireAndForget(UserData::getInstance().webHookBaseUrl,
                                                  UserData::getInstance().webhookPath, body, {});
            }
        }
    }
}
