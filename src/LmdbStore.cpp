#include "LmdbStore.h"

#include <cerrno>
#include <cstdlib>
#include <mutex>
#include <tuple>
#include <vector>

#include "Config.h"
#include "Logging.h"

MDB_env* env;

/** Single shared LMDB database handle, opened once in init_env and reused for the
 *  lifetime of the process. LMDB DBI handles are meant to be opened once and shared;
 *  opening/closing one inside every transaction takes a lock and is wasteful. */
MDB_dbi g_dbi;

std::mutex write_worker_mutex;

void init_env() {
    if (mdb_env_create(&env) != 0) {
        log(LogLevel::ERROR, "Failed to create LMDB environment.");
        exit(-1);
    }

    if (mdb_env_set_mapsize(env, UserData::getInstance().lmdbDatabaseSizeInBytes) != 0) {
        log(LogLevel::ERROR, "Failed to set map size.");
        exit(-1);
    }

    if (mdb_env_set_maxreaders(env, 128) != 0) {
        log(LogLevel::ERROR, "Failed to set max readers.");
        exit(-1);
    }

    if (mdb_env_set_maxdbs(env, 1) != 0) {
        log(LogLevel::ERROR, "Failed to set max databases.");
        exit(-1);
    }

    if (mdb_env_open(env, "./messages_db", MDB_WRITEMAP, 0664) != 0) {
        log(LogLevel::ERROR, "Failed to open LMDB environment.");
        exit(-1);
    }

    /** Open the single shared database handle once and keep it for the process
     *  lifetime (reused by all read/write/delete transactions). */
    {
        MDB_txn* txn;
        if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
            log(LogLevel::ERROR, "Failed to begin txn for dbi open.");
            exit(-1);
        }
        if (mdb_dbi_open(txn, "messages_db", MDB_CREATE, &g_dbi) != 0) {
            log(LogLevel::ERROR, "Failed to open LMDB database handle.");
            mdb_txn_abort(txn);
            exit(-1);
        }
        if (mdb_txn_commit(txn) != 0) {
            log(LogLevel::ERROR, "Failed to commit dbi open txn.");
            exit(-1);
        }
    }

    log(LogLevel::INFO, "LMDB environment initialized successfully.");
}

/** write the data to the LMDB, LMDB has internal locking mechanish so no need to mutexes */
void write_worker(const std::string& room_id, const std::string& message_content, bool needsCommit) {
    MDB_txn* txn;

    thread_local std::vector<std::tuple<std::string, std::string>> batch;

    if (!needsCommit) {
        batch.push_back({room_id, message_content});
    }

    /** commit once the batch reaches its size limit, or when a commit is forced */
    if (batch.size() >= UserData::getInstance().lmdbCommitBatchSize || (needsCommit && batch.size() > 0)) {
        if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
            log(LogLevel::ERROR, "Failed to begin write transaction.");
            batch.clear();
            return;
        }

        for (const auto& [key_str, value_str] : batch) {
            MDB_val key, value;

            key.mv_size = key_str.size();
            key.mv_data = (void*)key_str.data();

            value.mv_size = value_str.size();
            value.mv_data = (void*)value_str.data();

            if (mdb_put(txn, g_dbi, &key, &value, 0) != 0) {
                log(LogLevel::ERROR, "Failed to write key : ", key_str);
                batch.clear();
                mdb_txn_abort(txn);
                return;
            }
        }

        /** mdb_txn_commit frees the txn even on failure — do NOT abort it afterwards */
        if (mdb_txn_commit(txn) != 0) {
            log(LogLevel::ERROR, "Failed to commit transaction.");
            batch.clear();
            return;
        }

        batch.clear();
    }
}

/** This function will delete the entry stored under the exact room_id key */
void delete_worker(const std::string& room_id) {
    MDB_txn* txn;
    MDB_val key;

    std::lock_guard<std::mutex> lock(write_worker_mutex);

    if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
        log(LogLevel::ERROR, "Failed to begin delete transaction.");
        return;
    }

    key.mv_data = (void*)room_id.c_str();
    key.mv_size = room_id.size();

    if (mdb_del(txn, g_dbi, &key, nullptr) != 0) {
        /** normal when a cache room vacates without ever storing a message */
        log(LogLevel::DEBUG, "Failed to delete key : ", room_id);
        mdb_txn_abort(txn);
        return;
    }

    if (mdb_txn_commit(txn) != 0) {
        log(LogLevel::ERROR, "Failed to commit delete transaction.");
    }
}

std::string read_worker(const std::string& room_id) {
    MDB_txn* txn;
    MDB_val key, value;

    if (mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn) != 0) {
        log(LogLevel::ERROR, "Failed to begin read transaction : ", mdb_strerror(errno));
        return "{}";
    }

    key.mv_size = room_id.size();
    key.mv_data = (void*)room_id.data();

    if (mdb_get(txn, g_dbi, &key, &value) == 0) {
        std::string message_content((char*)value.mv_data, value.mv_size);

        mdb_txn_commit(txn);

        return message_content;
    }

    /** a missing key is a normal cache miss (empty/new room), not an error */
    log(LogLevel::DEBUG, "No message found for room_id : ", room_id);
    mdb_txn_abort(txn);
    return "{}";
}
