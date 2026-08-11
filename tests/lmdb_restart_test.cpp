// Restart-continuity check for the LMDB history: a message written after a restart
// must sort AFTER everything written before it (the arrival sequence is seeded from
// the persisted high-water). Run twice against the SAME ./messages_db:
//   pass 1 (arg "write"): writes a, b        -> expect [b,a]
//   pass 2 (arg "append"): writes c          -> expect [c,b,a]
#include <cstdio>
#include <string>
#include <vector>

#include "Config.h"
#include "LmdbStore.h"

static void put(const std::string& rid, const std::string& msg) {
    write_worker(rid, msg, false);
    write_worker("", "", true);
}
static std::vector<std::string> parseArr(const std::string& s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] == '"') {
            size_t j = i + 1;
            std::string cur;
            while (j < s.size() && s[j] != '"') {
                if (s[j] == '\\' && j + 1 < s.size()) {
                    cur.push_back(s[j + 1]);
                    j += 2;
                } else {
                    cur.push_back(s[j]);
                    j++;
                }
            }
            out.push_back(cur);
            i = j + 1;
        } else
            i++;
    }
    return out;
}

int main(int argc, char** argv) {
    init_env();
    const std::string rid = "pub-cache-restart";
    std::string mode = argc > 1 ? argv[1] : "write";
    int failures = 0;

    if (mode == "write") {
        put(rid, "a");
        put(rid, "b");
        auto v = parseArr(read_worker(rid, 100));
        bool ok = v.size() == 2 && v[0] == "b" && v[1] == "a";
        printf("  %s pass1 [b,a]\n", ok ? "ok  " : "FAIL");
        if (!ok)
            failures++;
    } else {
        put(rid, "c");
        auto v = parseArr(read_worker(rid, 100));
        bool ok = v.size() == 3 && v[0] == "c" && v[1] == "b" && v[2] == "a";
        printf("  %s pass2 [c,b,a] (seq survived restart)\n", ok ? "ok  " : "FAIL");
        if (!ok) {
            printf("      got:");
            for (auto& s : v)
                printf(" %s", s.c_str());
            printf("\n");
            failures++;
        }
    }
    printf("%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
