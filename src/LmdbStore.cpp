#include "LmdbStore.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "Config.h"
#include "Logging.h"
#include "Util.h"

MDB_env* env;

/** Single shared LMDB database handle, opened once in init_env and reused for the
 *  lifetime of the process. */
MDB_dbi g_dbi;

/*
 * Key layout — each cache room keeps a bounded HISTORY, not just its latest
 * message. LMDB is an ordered B+tree, so we make a room's messages contiguous and
 * chronologically ordered with a composite key:
 *
 *     message key : <rid> '\0' <8-byte big-endian sequence>
 *     room meta   : <rid> '\1'                 (value = current history byte count)
 *     global meta : '\0'                       (value = high-water sequence)
 *
 * '\0' < '\1', so a room's messages sort before its meta key; '\0' as the first
 * byte of the global meta sorts before any real room id (rooms are "pub-cache-…").
 * The separator also prevents prefix collisions ("abc\0…" always sorts before
 * "abcd\0…"). Reads are reverse cursor scans (newest first); eviction deletes the
 * oldest key in a room's range; all within the single batch write transaction.
 */
namespace {
    constexpr char SEP_MSG = '\0';   /* rid <SEP_MSG> seq  -> a message */
    constexpr char SEP_META = '\1';  /* rid <SEP_META>     -> room byte-count meta */
    const std::string GLOBAL_SEQ_KEY(1, '\0');

    /** global arrival sequence; seeded from GLOBAL_SEQ_KEY at startup so ordering
     *  survives restarts (a new message always sorts after every old one) */
    std::atomic<uint64_t> g_seq{1};

    void putBE64(std::string& out, uint64_t v) {
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<char>((v >> (i * 8)) & 0xFF));
    }
    uint64_t getBE64(const void* p, size_t n) {
        uint64_t v = 0;
        const unsigned char* b = static_cast<const unsigned char*>(p);
        for (size_t i = 0; i < n && i < 8; ++i)
            v = (v << 8) | b[i];
        return v;
    }

    std::string msgKey(const std::string& rid, uint64_t seq) {
        std::string k;
        k.reserve(rid.size() + 1 + 8);
        k += rid;
        k.push_back(SEP_MSG);
        putBE64(k, seq);
        return k;
    }
    std::string roomMetaKey(const std::string& rid) {
        std::string k = rid;
        k.push_back(SEP_META);
        return k;
    }
    /** true if `key` (of length keyLen) is one of `rid`'s message keys */
    bool isRoomMsgKey(const void* key, size_t keyLen, const std::string& rid) {
        return keyLen >= rid.size() + 1 && std::memcmp(key, rid.data(), rid.size()) == 0 &&
               static_cast<const char*>(key)[rid.size()] == SEP_MSG;
    }

    MDB_val val(const std::string& s) {
        MDB_val v;
        v.mv_size = s.size();
        v.mv_data = const_cast<char*>(s.data());
        return v;
    }
} // namespace

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

    /** Seed the arrival sequence from the persisted high-water so ordering (and
     *  eviction) stays correct across restarts. */
    {
        MDB_txn* txn;
        if (mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn) == 0) {
            MDB_val k = val(GLOBAL_SEQ_KEY), v;
            if (mdb_get(txn, g_dbi, &k, &v) == 0 && v.mv_size == 8) {
                g_seq.store(getBE64(v.mv_data, v.mv_size) + 1, std::memory_order_relaxed);
            }
            mdb_txn_abort(txn);
        }
    }

    log(LogLevel::INFO, "LMDB environment initialized successfully (history mode, ",
        UserData::getInstance().cacheHistoryBytesPerRoom / (1024 * 1024), " MiB/room).");
}

void write_worker(const std::string& room_id, const std::string& message_content, bool needsCommit) {
    /** (rid, seq, message) stamped with the global arrival order at push time */
    thread_local std::vector<std::tuple<std::string, uint64_t, std::string>> batch;

    if (!needsCommit) {
        uint64_t seq = g_seq.fetch_add(1, std::memory_order_relaxed);
        batch.emplace_back(room_id, seq, message_content);
    }

    if (batch.size() >= static_cast<size_t>(UserData::getInstance().lmdbCommitBatchSize) ||
        (needsCommit && !batch.empty())) {

        const unsigned long long perRoomLimit = UserData::getInstance().cacheHistoryBytesPerRoom;

        MDB_txn* txn;
        if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
            log(LogLevel::ERROR, "Failed to begin write transaction.");
            batch.clear();
            return;
        }

        uint64_t maxSeq = 0;
        /** message bytes appended per room this batch, to fold into the meta count */
        std::unordered_map<std::string, unsigned long long> added;

        bool failed = false;
        for (const auto& [rid, seq, msg] : batch) {
            std::string k = msgKey(rid, seq);
            MDB_val mk = val(k), mv = val(msg);
            int rc = mdb_put(txn, g_dbi, &mk, &mv, 0);
            if (rc != 0) {
                /** MDB_MAP_FULL (the 10 GB map is exhausted) or any other error:
                 *  drop this batch rather than crash. Per-room eviction bounds each
                 *  room; this bounds the pathological many-rooms case. */
                log(LogLevel::ERROR, "LMDB write failed (", mdb_strerror(rc), "); dropping batch");
                failed = true;
                break;
            }
            if (seq > maxSeq)
                maxSeq = seq;
            added[rid] += msg.size();
        }

        if (failed) {
            mdb_txn_abort(txn);
            batch.clear();
            return;
        }

        /** Per room touched: fold in the new bytes, then evict oldest until within
         *  the byte budget. Eviction work is proportional to bytes removed, not room
         *  size. */
        for (const auto& [rid, addedBytes] : added) {
            std::string metaK = roomMetaKey(rid);
            MDB_val mk = val(metaK), mv;
            unsigned long long bytes = 0;
            if (mdb_get(txn, g_dbi, &mk, &mv) == 0 && mv.mv_size == 8)
                bytes = getBE64(mv.mv_data, mv.mv_size);
            bytes += addedBytes;

            if (perRoomLimit > 0 && bytes > perRoomLimit) {
                MDB_cursor* cur;
                if (mdb_cursor_open(txn, g_dbi, &cur) == 0) {
                    std::string startK = rid;
                    startK.push_back(SEP_MSG); /* first possible message key for rid */
                    MDB_val ck = val(startK), cv;
                    int rc = mdb_cursor_get(cur, &ck, &cv, MDB_SET_RANGE);
                    while (rc == 0 && bytes > perRoomLimit && isRoomMsgKey(ck.mv_data, ck.mv_size, rid)) {
                        unsigned long long sz = cv.mv_size;
                        int drc = mdb_cursor_del(cur, 0);
                        if (drc != 0)
                            break;
                        bytes = (bytes > sz) ? bytes - sz : 0;
                        rc = mdb_cursor_get(cur, &ck, &cv, MDB_NEXT);
                    }
                    mdb_cursor_close(cur);
                }
            }

            std::string bv;
            putBE64(bv, bytes);
            MDB_val wmk = val(metaK), wmv = val(bv);
            mdb_put(txn, g_dbi, &wmk, &wmv, 0);
        }

        /** persist the sequence high-water (max with existing, since writers commit
         *  in an arbitrary order relative to their stamped seqs) */
        {
            MDB_val gk = val(GLOBAL_SEQ_KEY), gv;
            uint64_t stored = 0;
            if (mdb_get(txn, g_dbi, &gk, &gv) == 0 && gv.mv_size == 8)
                stored = getBE64(gv.mv_data, gv.mv_size);
            if (maxSeq > stored) {
                std::string sv;
                putBE64(sv, maxSeq);
                MDB_val wgk = val(GLOBAL_SEQ_KEY), wgv = val(sv);
                mdb_put(txn, g_dbi, &wgk, &wgv, 0);
            }
        }

        if (mdb_txn_commit(txn) != 0) {
            log(LogLevel::ERROR, "Failed to commit transaction.");
        }
        batch.clear();
    }
}

void delete_worker(const std::string& room_id) {
    MDB_txn* txn;
    if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
        log(LogLevel::ERROR, "Failed to begin delete transaction.");
        return;
    }

    MDB_cursor* cur;
    if (mdb_cursor_open(txn, g_dbi, &cur) == 0) {
        std::string startK = room_id;
        startK.push_back(SEP_MSG);
        MDB_val ck = val(startK), cv;
        int rc = mdb_cursor_get(cur, &ck, &cv, MDB_SET_RANGE);
        while (rc == 0 && isRoomMsgKey(ck.mv_data, ck.mv_size, room_id)) {
            mdb_cursor_del(cur, 0);
            rc = mdb_cursor_get(cur, &ck, &cv, MDB_NEXT);
        }
        mdb_cursor_close(cur);
    }

    std::string metaK = roomMetaKey(room_id);
    MDB_val mk = val(metaK);
    mdb_del(txn, g_dbi, &mk, nullptr); /* ignore "not found" */

    if (mdb_txn_commit(txn) != 0) {
        log(LogLevel::ERROR, "Failed to commit delete transaction.");
    }
}

std::string read_worker(const std::string& room_id, size_t limit) {
    MDB_txn* txn;
    if (int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn); rc != 0) {
        log(LogLevel::ERROR, "Failed to begin read transaction : ", mdb_strerror(rc));
        return "[]";
    }

    std::string out = "[";
    bool first = true;

    MDB_cursor* cur;
    if (mdb_cursor_open(txn, g_dbi, &cur) == 0) {
        /** newest first: position at the room's meta key (just past its last
         *  message) and step backwards through the message range */
        std::string upper = roomMetaKey(room_id);
        MDB_val ck = val(upper), cv;
        int rc = mdb_cursor_get(cur, &ck, &cv, MDB_SET_RANGE);
        if (rc == MDB_NOTFOUND)
            rc = mdb_cursor_get(cur, &ck, &cv, MDB_LAST); /* room is the last key overall */
        else
            rc = mdb_cursor_get(cur, &ck, &cv, MDB_PREV); /* step back into the messages */

        size_t n = 0;
        while (rc == 0 && n < limit && isRoomMsgKey(ck.mv_data, ck.mv_size, room_id)) {
            if (!first)
                out.push_back(',');
            first = false;
            out.push_back('"');
            appendJsonEscaped(out, std::string_view(static_cast<const char*>(cv.mv_data), cv.mv_size));
            out.push_back('"');
            ++n;
            rc = mdb_cursor_get(cur, &ck, &cv, MDB_PREV);
        }
        mdb_cursor_close(cur);
    }

    mdb_txn_abort(txn);
    out.push_back(']');
    return out;
}
