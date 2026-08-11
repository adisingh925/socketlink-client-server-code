// Direct unit test for the bounded per-room LMDB message history.
// Exercises write_worker/read_worker/delete_worker without the WS layer.
//
// Build (from repo root, deps in ~/sl-deps):
//   g++ -std=c++17 -O2 -Isrc tests/lmdb_history_test.cpp \
//       build/LmdbStore.o build/Config.o build/Util.o \
//       -llmdb -lssl -lcrypto -lpthread -o /tmp/lmdb_history_test
//   rm -rf ./messages_db && /tmp/lmdb_history_test
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "Config.h"
#include "LmdbStore.h"

// The real logger lives in main.cpp (not linked here) — provide a stub so the
// store's log() calls resolve. Signature matches the variadic template? No — log
// is a template; LmdbStore.o already contains its instantiations, so we only need
// the primitives it calls. Simplest: LmdbStore uses log(LogLevel,...) which is a
// header template that ultimately writes via a sink. We stub that sink.
// (If linking complains, the header template emitted into LmdbStore.o references
//  a concrete function — see Logging.h.)

static int failures = 0;
static void check(const char* label, bool ok) {
    printf("  %s %s\n", ok ? "ok  " : "FAIL", label);
    if (!ok) failures++;
}

// Push a message then force a flush so it is durable immediately.
static void put(const std::string& rid, const std::string& msg) {
    write_worker(rid, msg, false);
    write_worker("", "", true); // flush this thread's batch
}

// Parse the JSON array of quoted strings into a vector (test payloads contain no
// escapes, so a light splitter suffices).
static std::vector<std::string> parseArr(const std::string& s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] == '"') {
            size_t j = i + 1;
            std::string cur;
            while (j < s.size() && s[j] != '"') {
                if (s[j] == '\\' && j + 1 < s.size()) { cur.push_back(s[j + 1]); j += 2; }
                else { cur.push_back(s[j]); j++; }
            }
            out.push_back(cur);
            i = j + 1;
        } else i++;
    }
    return out;
}

int main() {
    init_env();

    const std::string rid = "pub-cache-room1";
    const std::string rid2 = "pub-cache-room2";

    // 1. Ordering: newest first.
    put(rid, "m1");
    put(rid, "m2");
    put(rid, "m3");
    {
        auto a = parseArr(read_worker(rid, 100));
        check("history size == 3", a.size() == 3);
        check("newest first [0]==m3", a.size() > 0 && a[0] == "m3");
        check("[1]==m2", a.size() > 1 && a[1] == "m2");
        check("[2]==m1", a.size() > 2 && a[2] == "m1");
    }

    // 2. limit caps the count, still newest-first.
    {
        auto a = parseArr(read_worker(rid, 2));
        check("limit=2 -> 2 entries", a.size() == 2);
        check("limit newest [0]==m3", a.size() > 0 && a[0] == "m3");
        check("limit [1]==m2", a.size() > 1 && a[1] == "m2");
    }

    // 3. Room isolation.
    put(rid2, "x1");
    {
        auto a = parseArr(read_worker(rid2, 100));
        check("room2 isolated size==1", a.size() == 1 && a[0] == "x1");
        auto b = parseArr(read_worker(rid, 100));
        check("room1 untouched size==3", b.size() == 3);
    }

    // 4. Eviction: with a low per-room byte cap, oldest are dropped.
    //    The config default is 5 MB; override the live snapshot to something tiny
    //    so we can test eviction without writing megabytes.
    {
        UserData* u = new UserData(UserData::getInstance());
        u->cacheHistoryBytesPerRoom = 25; // ~ a few 10-byte messages
        UserData::publish(u);
    }
    const std::string er = "pub-cache-evict";
    // each message is 10 bytes -> cap 25 keeps at most 2 newest (20 bytes)
    for (int i = 0; i < 6; i++) put(er, "0123456789");
    {
        auto a = parseArr(read_worker(er, 100));
        check("eviction keeps <=2 (cap 25 / 10B msgs)", a.size() <= 2 && a.size() >= 1);
        check("eviction keeps newest content", a.size() > 0 && a[0] == "0123456789");
    }

    // restore a generous cap for the remaining tests
    {
        UserData* u = new UserData(UserData::getInstance());
        u->cacheHistoryBytesPerRoom = 5ULL * 1024 * 1024;
        UserData::publish(u);
    }

    // 5. Range delete (vacate) removes all of a room's history.
    delete_worker(rid);
    {
        auto a = parseArr(read_worker(rid, 100));
        check("delete_worker clears room1", a.size() == 0);
        auto b = parseArr(read_worker(rid2, 100));
        check("delete_worker leaves room2 intact", b.size() == 1);
    }

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
