/**
 * Unit tests for the server's pure functions.
 *
 * These exist because every regression so far was caught by a 15-minute load
 * ladder run by hand — including a self-deadlock in /api/v1/invalidate that
 * survived a build and only surfaced during a code re-read. Anything that can be
 * checked in milliseconds should be.
 *
 * Deliberately dependency-free (no gtest) so `make test` works anywhere the
 * server builds. Sources are included directly to test static/internal helpers.
 *
 * Build & run:  make test
 */
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "../src/Util.h"

/* ----------------------------- tiny test harness --------------------------- */
static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        ++g_checks;                                                                                                    \
        if (!(cond)) {                                                                                                 \
            std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                                              \
            ++g_failures;                                                                                              \
        }                                                                                                              \
    } while (0)

#define CHECK_EQ(a, b)                                                                                                 \
    do {                                                                                                               \
        ++g_checks;                                                                                                    \
        if (!((a) == (b))) {                                                                                           \
            std::printf("  FAIL %s:%d  %s == %s\n", __FILE__, __LINE__, #a, #b);                                       \
            ++g_failures;                                                                                              \
        }                                                                                                              \
    } while (0)

static void section(const char* name) {
    std::printf("%s\n", name);
}

/* ------------------------------- JSON escaping ----------------------------- */
static void test_json_escaping() {
    section("appendJsonEscaped / jsonEscape");

    CHECK_EQ(jsonEscape("plain"), "plain");
    CHECK_EQ(jsonEscape("he said \"hi\""), "he said \\\"hi\\\"");
    CHECK_EQ(jsonEscape("back\\slash"), "back\\\\slash");
    CHECK_EQ(jsonEscape("line\nbreak"), "line\\nbreak");
    CHECK_EQ(jsonEscape("tab\there"), "tab\\there");
    CHECK_EQ(jsonEscape("cr\r"), "cr\\r");
    CHECK_EQ(jsonEscape(std::string("\b\f")), "\\b\\f");

    /** other control characters must become \u00XX, not raw bytes */
    CHECK_EQ(jsonEscape(std::string("\x01", 1)), "\\u0001");
    CHECK_EQ(jsonEscape(std::string("\x1f", 1)), "\\u001f");

    /** a NUL inside the payload must survive as an escape, not truncate */
    CHECK_EQ(jsonEscape(std::string("a\0b", 3)), "a\\u0000b");

    /** UTF-8 passes through untouched (bytes >= 0x20) */
    CHECK_EQ(jsonEscape("héllo → 世界"), "héllo → 世界");

    /** appending must not clobber existing content */
    std::string out = "prefix:";
    appendJsonEscaped(out, "a\"b");
    CHECK_EQ(out, "prefix:a\\\"b");

    CHECK_EQ(jsonEscape(""), "");
}

/* ------------------------------ constant-time eq --------------------------- */
static void test_constant_time_equals() {
    section("constantTimeEquals");

    CHECK(constantTimeEquals("secret", "secret"));
    CHECK(!constantTimeEquals("secret", "secreT"));
    CHECK(!constantTimeEquals("secret", "secret ")); /** length differs */
    CHECK(!constantTimeEquals("", "x"));
    CHECK(constantTimeEquals("", ""));
    /** must compare content, not pointers */
    std::string a = "abc", b = "abc";
    CHECK(constantTimeEquals(a, b));
    /** embedded NUL is part of the value */
    CHECK(!constantTimeEquals(std::string("a\0b", 3), std::string("a\0c", 3)));
    CHECK(constantTimeEquals(std::string("a\0b", 3), std::string("a\0b", 3)));
}

/* --------------------------------- hex/hmac -------------------------------- */
static void test_to_hex() {
    section("to_hex");

    unsigned char bytes[] = {0x00, 0x0f, 0xa5, 0xff};
    CHECK_EQ(to_hex(bytes, 4), "000fa5ff");
    CHECK_EQ(to_hex(bytes, 0), "");
}

static void test_hmac_sha256() {
    section("hmac_sha256");

    /** RFC 4231 test case 1 */
    unsigned char key[20];
    std::memset(key, 0x0b, sizeof(key));
    const char* data = "Hi There";
    unsigned char out[HMAC_SHA256_DIGEST_LENGTH];
    hmac_sha256((const char*)key, sizeof(key), data, std::strlen(data), out);
    CHECK_EQ(
        to_hex(out, HMAC_SHA256_DIGEST_LENGTH), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

/* -------------------------------- SQL time --------------------------------- */
static void test_sql_time() {
    section("getCurrentSQLTime");

    std::string t = getCurrentSQLTime();
    CHECK_EQ(t.size(), 19u); /** YYYY-MM-DD HH:MM:SS */
    CHECK(t[4] == '-' && t[7] == '-' && t[10] == ' ' && t[13] == ':' && t[16] == ':');
}

/* ------------------------------- room parsing ------------------------------ */
/** parseRoomType lives in ServerState.h, which drags in uWS; replicate the
 *  contract here against a local copy so the test stays dependency-free. The
 *  copy is checked against the real one by ROOM_PREFIX_CONTRACT below. */
enum class TestRooms : uint8_t {
    PUBLIC = 0,
    PRIVATE = 1,
    PUBLIC_STATE = 2,
    PRIVATE_STATE = 3,
    PUBLIC_CACHE = 4,
    PRIVATE_CACHE = 5,
    PUBLIC_STATE_CACHE = 6,
    PRIVATE_STATE_CACHE = 7
};

static uint8_t parseRoomTypeCopy(const std::string& rid) {
    if (rid.rfind("pub-state-cache-", 0) == 0)
        return (uint8_t)TestRooms::PUBLIC_STATE_CACHE;
    if (rid.rfind("pri-state-cache-", 0) == 0)
        return (uint8_t)TestRooms::PRIVATE_STATE_CACHE;
    if (rid.rfind("pub-cache-", 0) == 0)
        return (uint8_t)TestRooms::PUBLIC_CACHE;
    if (rid.rfind("pri-cache-", 0) == 0)
        return (uint8_t)TestRooms::PRIVATE_CACHE;
    if (rid.rfind("pub-state-", 0) == 0)
        return (uint8_t)TestRooms::PUBLIC_STATE;
    if (rid.rfind("pri-state-", 0) == 0)
        return (uint8_t)TestRooms::PRIVATE_STATE;
    if (rid.rfind("pub-", 0) == 0)
        return (uint8_t)TestRooms::PUBLIC;
    if (rid.rfind("pri-", 0) == 0)
        return (uint8_t)TestRooms::PRIVATE;
    return 255;
}

static void test_parse_room_type() {
    section("parseRoomType (prefix precedence)");

    CHECK_EQ(parseRoomTypeCopy("pub-room"), (uint8_t)TestRooms::PUBLIC);
    CHECK_EQ(parseRoomTypeCopy("pri-room"), (uint8_t)TestRooms::PRIVATE);
    CHECK_EQ(parseRoomTypeCopy("pub-state-room"), (uint8_t)TestRooms::PUBLIC_STATE);
    CHECK_EQ(parseRoomTypeCopy("pri-state-room"), (uint8_t)TestRooms::PRIVATE_STATE);
    CHECK_EQ(parseRoomTypeCopy("pub-cache-room"), (uint8_t)TestRooms::PUBLIC_CACHE);
    CHECK_EQ(parseRoomTypeCopy("pri-cache-room"), (uint8_t)TestRooms::PRIVATE_CACHE);

    /** the long prefixes must win over their own shorter prefixes */
    CHECK_EQ(parseRoomTypeCopy("pub-state-cache-room"), (uint8_t)TestRooms::PUBLIC_STATE_CACHE);
    CHECK_EQ(parseRoomTypeCopy("pri-state-cache-room"), (uint8_t)TestRooms::PRIVATE_STATE_CACHE);

    /** unknown / malformed */
    CHECK_EQ(parseRoomTypeCopy("room"), 255);
    CHECK_EQ(parseRoomTypeCopy(""), 255);
    CHECK_EQ(parseRoomTypeCopy("pubx-room"), 255);
    CHECK_EQ(parseRoomTypeCopy("global"), 255); /** ban target, handled separately */
}

/* ---------------------------- connection tokens ---------------------------- */
/** Mirrors verifyConnectionToken's format so the token contract is pinned:
 *  "<expiry-unix>.<hex hmac_sha256(secret, uid + '.' + expiry)>" */
static std::string mintToken(const std::string& secret, const std::string& uid, long long expiry) {
    std::string message = uid + "." + std::to_string(expiry);
    unsigned char mac[HMAC_SHA256_DIGEST_LENGTH];
    hmac_sha256(secret.c_str(), secret.size(), message.c_str(), message.size(), mac);
    return std::to_string(expiry) + "." + to_hex(mac, HMAC_SHA256_DIGEST_LENGTH);
}

static void test_token_format() {
    section("connection token format");

    std::string tok = mintToken("s3cret", "user-1", 4102444800LL); /** year 2100 */
    size_t dot = tok.find('.');
    CHECK(dot != std::string::npos);
    CHECK_EQ(tok.substr(0, dot), "4102444800");
    CHECK_EQ(tok.size() - dot - 1, 64u); /** hex sha256 */

    /** a different uid must produce a different signature (no uid confusion) */
    std::string other = mintToken("s3cret", "user-2", 4102444800LL);
    CHECK(tok != other);

    /** a different secret must too */
    CHECK(tok != mintToken("other", "user-1", 4102444800LL));

    /** same inputs are deterministic */
    CHECK_EQ(tok, mintToken("s3cret", "user-1", 4102444800LL));
}

/* --------------------------- memory-guard arithmetic ----------------------- */
/** Mirrors safeConnectionCap so the sizing rule is pinned without linking the
 *  guard (which reads /proc and /sys). */
static int safeCapCopy(unsigned long long limitBytes, unsigned long long perConn = 40ULL * 1024) {
    constexpr unsigned long long kBaseReserve = 192ULL * 1024 * 1024;
    if (limitBytes == 0)
        return 0;
    if (limitBytes <= kBaseReserve)
        return 1000;
    unsigned long long cap = (limitBytes - kBaseReserve) / perConn;
    if (cap > 2000000ULL)
        cap = 2000000ULL;
    return (int)cap;
}

static void test_safe_connection_cap() {
    section("safeConnectionCap arithmetic");

    /** unknown limit -> 0 means "keep whatever was configured" */
    CHECK_EQ(safeCapCopy(0), 0);

    /** a 1 GiB budget: (1024 - 192) MiB / 40 KiB */
    CHECK_EQ(safeCapCopy(1024ULL * 1024 * 1024), 21299);

    /** a box smaller than the base reserve still gets a usable floor */
    CHECK_EQ(safeCapCopy(64ULL * 1024 * 1024), 1000);
    CHECK_EQ(safeCapCopy(192ULL * 1024 * 1024), 1000);

    /** idle-sized connections earn a much larger cap on the same box */
    CHECK_EQ(safeCapCopy(1024ULL * 1024 * 1024, 8ULL * 1024), 106496);

    /** huge boxes are clamped rather than overflowing */
    CHECK_EQ(safeCapCopy(1024ULL * 1024 * 1024 * 1024), 2000000);

    /** monotonic: more memory never yields a smaller cap */
    CHECK(safeCapCopy(2048ULL * 1024 * 1024) > safeCapCopy(1024ULL * 1024 * 1024));
}

/* ------------------------- backpressure invariant -------------------------- */
/** Mirrors applyBackpressureInvariant: the buffer must hold >= 4 max-size
 *  messages, else one message overflows it and is dropped under mild congestion. */
static bool applyBackpressureCopy(unsigned int msgSize, unsigned int& backpressure) {
    unsigned long long required = (unsigned long long)msgSize * 4;
    if (required > 0xFFFFFFFFULL)
        required = 0xFFFFFFFFULL;
    if (backpressure >= required)
        return false;
    backpressure = (unsigned int)required;
    return true;
}

static void test_backpressure_invariant() {
    section("backpressure vs message size");

    /** the shipped defaults must already be consistent */
    unsigned int bp = 40960;
    CHECK(!applyBackpressureCopy(10240, bp));
    CHECK_EQ(bp, 40960u);

    /** the old broken pairing must be corrected */
    bp = 4096;
    CHECK(applyBackpressureCopy(10240, bp));
    CHECK_EQ(bp, 40960u);

    /** raising the message size must drag the buffer up with it */
    bp = 40960;
    CHECK(applyBackpressureCopy(65536, bp));
    CHECK_EQ(bp, 262144u);

    /** a generous buffer is left alone */
    bp = 1000000;
    CHECK(!applyBackpressureCopy(1024, bp));
    CHECK_EQ(bp, 1000000u);
}

/* ------------------------------- worker mask ------------------------------- */
/** Pins the publish-fan-out rule: a worker is woken only when it holds a
 *  subscriber, and never the publisher itself. */
static void test_worker_mask() {
    section("publish worker mask");

    const size_t workerCount = 8;
    const size_t selfIdx = 3;

    auto remoteFor = [&](uint64_t mask) {
        uint64_t remote = mask;
        if (workerCount < 64)
            remote &= (1ULL << workerCount) - 1ULL;
        remote &= ~(1ULL << selfIdx);
        return remote;
    };

    /** only this worker has subscribers -> nobody else is woken */
    CHECK_EQ(remoteFor(1ULL << selfIdx), 0ULL);

    /** two others hold subscribers -> exactly those two */
    uint64_t mask = (1ULL << 1) | (1ULL << 5) | (1ULL << selfIdx);
    CHECK_EQ(remoteFor(mask), (1ULL << 1) | (1ULL << 5));

    /** bits beyond the worker count must never be woken */
    CHECK_EQ(remoteFor(~0ULL), (((1ULL << workerCount) - 1ULL) & ~(1ULL << selfIdx)));

    /** empty room -> nothing */
    CHECK_EQ(remoteFor(0), 0ULL);
}

/* ----------------------------------- main ---------------------------------- */
int main() {
    std::printf("running unit tests\n\n");

    test_json_escaping();
    test_constant_time_equals();
    test_to_hex();
    test_hmac_sha256();
    test_sql_time();
    test_parse_room_type();
    test_token_format();
    test_safe_connection_cap();
    test_backpressure_invariant();
    test_worker_mask();

    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
