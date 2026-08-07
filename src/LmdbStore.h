#pragma once

#include <lmdb.h>

#include <string>

/** LMDB environment + single shared database handle (opened once in init_env). */
extern MDB_env* env;
extern MDB_dbi g_dbi;

void init_env();

/** Buffer (room_id, message) into the CALLING THREAD's write batch; commits when
 *  the batch reaches lmdbCommitBatchSize, or immediately when needsCommit is true.
 *  The batch is thread-local: a flush only commits the calling thread's batch, so
 *  readers must fan a flush out to every worker loop (see the messages endpoint). */
void write_worker(const std::string& room_id, const std::string& message_content, bool needsCommit = false);

/** Delete the entry stored under the exact room_id key. */
void delete_worker(const std::string& room_id);

/** Read the entry stored under room_id ("{}" when absent). */
std::string read_worker(const std::string& room_id);
