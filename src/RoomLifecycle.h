#pragma once

#include <cstdint>
#include <string>

#include "ServerState.h"

/** Unsubscribe `ws` from `rid` and do the room-registry cleanup. Must run on the
 *  thread that owns `ws` unless isClosed (the .close handler path).
 *
 *  The uid comes from the socket itself (ws->getUserData()->uid) — the single
 *  source of truth — so a caller can no longer pass a mismatched one.
 *
 *  `rid` is deliberately BY VALUE: with isClosed == false this erases `rid` from
 *  ws->getUserData()->rooms, so a caller passing a reference to that map's own
 *  key would be left with a dangling reference for the rest of the call. The copy
 *  is the price of making that impossible. */
void closeConnection(SLWebSocket* ws, worker_t* worker, std::string rid, uint8_t roomType, bool isClosed = false);

/** Subscribe `ws` to `rid` and register it in the room maps. `rid` is only ever
 *  inserted (never erased from under itself), so a const reference is safe. */
void openConnection(SLWebSocket* ws, worker_t* worker, const std::string& rid, uint8_t roomType);
