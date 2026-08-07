#pragma once

#include <cstdint>
#include <string>

#include "ServerState.h"

/** Unsubscribe `uid` from `rid` and do the room-registry cleanup. Must run on the
 *  thread that owns `ws` unless isClosed (the .close handler path). */
void closeConnection(SLWebSocket* ws, worker_t* worker, std::string rid, std::string uid, uint8_t roomType,
                     bool isClosed = false);

/** Subscribe `ws` to `rid` and register it in the room maps. */
void openConnection(SLWebSocket* ws, worker_t* worker, std::string rid, uint8_t roomType);
