#pragma once

#include <lmdb.h>

#include <string>

/** LMDB environment + single shared database handle (opened once in init_env). */
extern MDB_env* env;
extern MDB_dbi g_dbi;

void init_env();

/** Append `message_content` to the CALLING THREAD's write batch (stamped with a
 *  global arrival sequence); commits when the batch reaches lmdbCommitBatchSize or
 *  immediately when needsCommit is true. Each commit appends the messages as
 *  history and evicts the oldest per room past cacheHistoryBytesPerRoom.
 *  The batch is thread-local: a flush only commits the calling thread's batch, so
 *  readers must fan a flush out to every worker loop (see the messages endpoint). */
void write_worker(const std::string& room_id, const std::string& message_content, bool needsCommit = false);

/** Schedule deletion of a room's history AS OF NOW: records the current arrival
 *  sequence and, at the calling thread's next write_worker flush (the 1s timer
 *  guarantees one), range-deletes every message with a LOWER sequence inside that
 *  flush's single transaction. Never commits on its own — a vacate storm costs zero
 *  extra LMDB commits (each commit msyncs under MDB_WRITEMAP), and a room that
 *  refills before the flush keeps its newer messages. Test code that reads back
 *  right away must flush first: write_worker("", "", true). */
void delete_worker(const std::string& room_id);

/** Return a room's history as a JSON array of message strings, NEWEST FIRST, up to
 *  `limit` entries ("[]" when empty). */
std::string read_worker(const std::string& room_id, size_t limit = 100);
