#include "App.h"
#include "json.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>
#include <lmdb.h>
#include <mysql/mysql.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <tbb/concurrent_hash_map.h>
#include <filesystem>
#include <fstream>
#include <deque>
#include <condition_variable>
#include <sys/resource.h>
#include "simdjson.h"

constexpr bool LOGS_ENABLED = true;

std::atomic<unsigned long long> totalMysqlDBWrites{0};

enum class LogLevel { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

/** Minimum level that is actually emitted (runtime-adjustable). Suppressed
 *  levels cost one relaxed atomic load and a branch at the call site. */
std::atomic<int> g_logLevel{static_cast<int>(LogLevel::INFO)};

/**
 * Asynchronous logger: call sites never perform I/O.
 *
 * The previous logger wrote to cout/cerr with std::endl (a flush) on the CALLING
 * thread, so a log line from a uWS event-loop handler stalled that worker's entire
 * reactor on terminal/journal I/O. Here callers only format the message and push it
 * onto a bounded queue; a dedicated thread timestamps, batches, and writes. The
 * queue drops the oldest entry when full (dropped count is tracked), so logging can
 * never block the server or grow memory without bound.
 */
class AsyncLogger {
public:
    static AsyncLogger& getInstance() {
        static AsyncLogger instance;
        return instance;
    }

    void enqueue(LogLevel level, std::string text) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.size() >= maxQueueSize_) {
                queue_.pop_front();
                dropped_.fetch_add(1, std::memory_order_relaxed);
            }
            queue_.push_back(Entry{level, std::chrono::system_clock::now(), std::move(text)});
        }
        cv_.notify_one();
    }

    unsigned long long droppedCount() const { return dropped_.load(std::memory_order_relaxed); }

    AsyncLogger(const AsyncLogger&) = delete;
    AsyncLogger& operator=(const AsyncLogger&) = delete;

private:
    struct Entry {
        LogLevel level;
        std::chrono::system_clock::time_point ts;
        std::string text;
    };

    AsyncLogger() : writer_([this]() { run(); }) {}

    ~AsyncLogger() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
        cv_.notify_all();
        if (writer_.joinable()) {
            writer_.join(); /** drains the queue: nothing is lost on clean exit */
        }
    }

    static const char* levelTag(LogLevel l) {
        switch (l) {
            case LogLevel::DEBUG:
                return "[DEBUG] ";
            case LogLevel::INFO:
                return "[INFO] ";
            case LogLevel::WARN:
                return "[WARN] ";
            default:
                return "[ERROR] ";
        }
    }

    void run() {
        std::deque<Entry> batch;
        std::string outBuf, errBuf;
        unsigned long long reportedDrops = 0;

        while (true) {
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this]() { return !queue_.empty() || !running_; });
                if (queue_.empty() && !running_) {
                    break;
                }
                batch.swap(queue_); /** take the whole backlog in one lock acquisition */
            }

            outBuf.clear();
            errBuf.clear();
            for (const auto& e : batch) {
                std::string& buf = (e.level == LogLevel::ERROR) ? errBuf : outBuf;

                std::time_t t = std::chrono::system_clock::to_time_t(e.ts);
                std::tm tm_buf;
                localtime_r(&t, &tm_buf);
                char ts[24];
                std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

                buf += '[';
                buf += ts;
                buf += "] ";
                buf += levelTag(e.level);
                buf += e.text;
                buf += '\n';
            }
            batch.clear();

            /** one write + one flush per batch, on this thread only */
            if (!outBuf.empty()) {
                fwrite(outBuf.data(), 1, outBuf.size(), stdout);
                fflush(stdout);
            }
            if (!errBuf.empty()) {
                fwrite(errBuf.data(), 1, errBuf.size(), stderr);
                fflush(stderr);
            }

            unsigned long long d = dropped_.load(std::memory_order_relaxed);
            if (d > reportedDrops) {
                std::string note =
                    "AsyncLogger: " + std::to_string(d - reportedDrops) + " log line(s) dropped (queue full)\n";
                fwrite(note.data(), 1, note.size(), stderr);
                fflush(stderr);
                reportedDrops = d;
            }
        }
    }

    std::deque<Entry> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool running_ = true;
    std::atomic<unsigned long long> dropped_{0};
    static constexpr size_t maxQueueSize_ = 65536;
    std::thread writer_;
};

/** Log a message. Cheap when suppressed (one atomic load); when emitted, the caller
 *  only formats the text — all I/O happens on the logger's own thread. */
template <typename... Args> void log(LogLevel level, const Args&... args) {
    if (!LOGS_ENABLED)
        return;
    if (static_cast<int>(level) < g_logLevel.load(std::memory_order_relaxed))
        return;

    std::ostringstream oss;
    (oss << ... << args);
    AsyncLogger::getInstance().enqueue(level, oss.str());
}

enum class Features : uint32_t {
    ENABLE_MYSQL_INTEGRATION = 1 << 0,
};

std::unordered_map<Features, int> featureStatus;
std::shared_mutex featureMutex;

/** read features, thread safe */
int getFeatureStatus(Features feature) {
    std::shared_lock<std::shared_mutex> lock(featureMutex);

    auto it = featureStatus.find(feature);
    return (it != featureStatus.end()) ? it->second : 0;
}

/** Fixed plaintext HTTP/WS listen port (TLS terminated upstream by a load
 *  balancer). Not configurable — the socket binds to this at startup. */
static constexpr int SL_LISTEN_PORT = 8080;

class UserData {
public:
    /** Server configuration. These in-class defaults ARE the compiled-in config for
     *  standalone mode (there is no config file); /api/v1/invalidate can override
     *  any of them at runtime. */
    unsigned int msgSizeAllowedInBytes = 10240; /* 10 KB max message */
    unsigned int maxBackpressureInBytes = 4096;
    unsigned short idleTimeoutInSeconds = 120;
    unsigned short maxLifetimeInMinutes = 0; /* 0 = no forced lifetime */

    int connections = 100000; /* hard cap on concurrent connections */
    /** Hardcoded API keys — change these and rebuild (or override at runtime via
     *  /api/v1/invalidate). Client key authenticates WS/pub-sub clients; admin key
     *  authenticates the admin REST endpoints. */
    std::string clientApiKey = "change-me-client-key";
    std::string adminApiKey = "change-me-admin-key";

    /** webhook configuration */
    std::string webHookBaseUrl;
    std::string webhookPath;
    std::string webhookSecret;
    uint64_t webhooks = 0;
    std::string webhookIP;

    /** mysql db configuration */
    int mysqlDBCommitBatchSize = 1000;
    std::string dbHost;
    int dbPort = 0;
    std::string dbUser;
    std::string dbPassword;
    std::string dbName;

    /** lmdb configurations */
    int lmdbCommitBatchSize = 1000;
    unsigned long long lmdbDatabaseSizeInBytes = 1ULL << 30; /* 1 GB message store */

    /** auto populated according to the values of above variables */
    uint32_t features = 0;

    UserData() = default;
    UserData(const UserData&) = default;
    UserData& operator=(const UserData&) = default;

    /**
     * Config is published as an immutable snapshot behind an atomic pointer.
     * getInstance() returns a const reference to the current snapshot, which is
     * never freed (old snapshots are intentionally leaked when a new one is
     * published — /invalidate is rare), so readers are lock-free and cannot race
     * with a concurrent update (previously populateUserData mutated these
     * std::string fields in place while other threads read them: a data race).
     *
     * To update: clone the current snapshot, modify the copy, then publish() it.
     * Serialize writers with configWriteMutex (see populateUserData).
     */
    static const UserData& getInstance() { return *current().load(std::memory_order_acquire); }

    /** Atomically install `next` as the current config (takes ownership; the
     *  previous snapshot is intentionally leaked). */
    static void publish(UserData* next) { current().store(next, std::memory_order_release); }

private:
    static std::atomic<UserData*>& current() {
        /** Meyers singleton avoids static-init-order issues. */
        static std::atomic<UserData*> ptr{new UserData()};
        return ptr;
    }
};

/** Serializes config writers (populateUserData) so concurrent /invalidate calls
 *  don't lose updates via clone-modify-publish races. */
std::mutex configWriteMutex;

/** Standalone / self-hosted mode: config is compiled in (see main()); there is no
 *  master server and no config file. /api/v1/invalidate is authenticated with the
 *  admin api key and can update the in-memory config snapshot at runtime. */

class MySQLConnectionHandler {
private:
    MYSQL* conn;
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> batch_data;

    class MySQLException : public std::runtime_error {
    public:
        explicit MySQLException(const std::string& message) : std::runtime_error(message) {}
    };

    /** Closes any existing connection and establishes a new one. */
    void createConnection() {
        try {
            if (getFeatureStatus(Features::ENABLE_MYSQL_INTEGRATION) == 0) {
                return;
            }

            if (conn) {
                mysql_close(conn);
                conn = nullptr;
            }

            conn = mysql_init(NULL);
            if (!conn) {
                log(LogLevel::ERROR, "MySQL Initialization Error");
            }

            /** connect timeout in seconds */
            unsigned int timeout = 3;
            mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

            if (!mysql_real_connect(conn, UserData::getInstance().dbHost.c_str(),
                                    UserData::getInstance().dbUser.c_str(), UserData::getInstance().dbPassword.c_str(),
                                    UserData::getInstance().dbName.c_str(), UserData::getInstance().dbPort, NULL, 0)) {
                log(LogLevel::ERROR, "MySQL Connection Error : " + std::string(mysql_error(conn)));
                mysql_close(conn);
                conn = nullptr;
            } else {
                mysql_query(conn, "SET SESSION query_cache_type = OFF");
                createTableIfNotExists();
                log(LogLevel::INFO, "MySQL connected: ", UserData::getInstance().dbHost, ":",
                    UserData::getInstance().dbPort, " db=", UserData::getInstance().dbName);
            }
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "MySQL Error : ", std::string(e.what()));
        }
    }

    /** Ensures there is an active MySQL connection, creating one if needed. */
    void checkConnection() {
        try {
            if (!conn) {
                createConnection();
            }
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "Connection Error : ", std::string(e.what()));
        }
    }

    void createTableIfNotExists() {
        try {
            if (!conn)
                return;

            const char* query = "CREATE TABLE IF NOT EXISTS socketlink_messages ("
                                "id INT AUTO_INCREMENT PRIMARY KEY,"
                                "insert_time DATETIME NOT NULL,"
                                "message TEXT NOT NULL,"
                                "uid VARCHAR(4096) NOT NULL,"
                                "rid VARCHAR(160) NOT NULL"
                                ")";

            if (mysql_query(conn, query)) {
                throw MySQLException("Table creation failed : " + std::string(mysql_error(conn)));
            }
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "Table Creation Error : ", std::string(e.what()));
        }
    }

    /** Inserts the batch via a parameterized statement (avoids SQL injection). */
    bool insertBatchData() {
        try {
            if (!conn) {
                return false;
            }

            std::string query = "INSERT INTO socketlink_messages (insert_time, message, uid, rid) VALUES ";
            for (size_t i = 0; i < batch_data.size(); ++i) {
                if (i > 0)
                    query += ", ";
                query += "(?, ?, ?, ?)";
            }

            MYSQL_STMT* stmt = mysql_stmt_init(conn);
            if (!stmt) {
                log(LogLevel::ERROR, "Batch Insertion Error : mysql_stmt_init failed (out of memory)");
                return false;
            }
            if (mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
                log(LogLevel::ERROR, "Batch Insertion Error : " + std::string(mysql_stmt_error(stmt)));
                mysql_stmt_close(stmt);
                return false;
            }

            /** heap-allocated to avoid a large VLA on the stack */
            std::vector<MYSQL_BIND> bind(4 * batch_data.size());
            std::memset(bind.data(), 0, sizeof(MYSQL_BIND) * bind.size());
            int paramIndex = 0;

            for (const auto& [insert_time, message, identifier, room] : batch_data) {
                bind[paramIndex].buffer_type = MYSQL_TYPE_STRING;
                bind[paramIndex].buffer = (void*)insert_time.c_str();
                bind[paramIndex].buffer_length = insert_time.length();
                paramIndex++;

                bind[paramIndex].buffer_type = MYSQL_TYPE_STRING;
                bind[paramIndex].buffer = (void*)message.c_str();
                bind[paramIndex].buffer_length = message.length();
                paramIndex++;

                bind[paramIndex].buffer_type = MYSQL_TYPE_STRING;
                bind[paramIndex].buffer = (void*)identifier.c_str();
                bind[paramIndex].buffer_length = identifier.length();
                paramIndex++;

                bind[paramIndex].buffer_type = MYSQL_TYPE_STRING;
                bind[paramIndex].buffer = (void*)room.c_str();
                bind[paramIndex].buffer_length = room.length();
                paramIndex++;
            }

            if (mysql_stmt_bind_param(stmt, bind.data()) || mysql_stmt_execute(stmt)) {
                mysql_stmt_close(stmt);
                log(LogLevel::ERROR, "Batch Insertion Error : " + std::string(mysql_stmt_error(stmt)));
                return false;
            }

            mysql_stmt_close(stmt);
            batch_data.clear();
            totalMysqlDBWrites.fetch_add(1, std::memory_order_relaxed);
            return true;
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "Batch Insertion Error : ", std::string(e.what()));

            return false;
        }
    }

public:
    MySQLConnectionHandler() : conn(nullptr) {
        try {
            createConnection();
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "Constructor Error : ", std::string(e.what()));
        }
    }

    ~MySQLConnectionHandler() {
        try {
            if (conn) {
                mysql_close(conn);
            }
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "Destructor Error : ", std::string(e.what()));
        }
    }

    /** Appends a message to the batch, flushing once a batch-size multiple is reached. */
    void insertSingleData(const std::string& insert_time, const std::string& message, const std::string& identifier,
                          const std::string& room) {
        try {
            /** Retried up to 3 batches' worth; beyond that the batch is dropped to bound memory use */
            if (batch_data.size() <= (UserData::getInstance().mysqlDBCommitBatchSize * 3)) {
                batch_data.emplace_back(insert_time, message, identifier, room);
                if (batch_data.size() % UserData::getInstance().mysqlDBCommitBatchSize == 0) {
                    insertBatchData();
                }
            } else {
                /** batch is not draining (DB unavailable); drop it to bound memory */
                batch_data.clear();
            }
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "Insert Data Error : ", std::string(e.what()));
        }
    }

    /** Forces insertion of any remaining batch data. */
    void flushRemainingData() {
        try {
            if (!batch_data.empty()) {
                insertBatchData();
            }
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "Flush Data Error : ", std::string(e.what()));
        }
    }

    void manualCreateConnection() {
        try {
            createConnection();
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "Manual Connection Error : ", std::string(e.what()));
        }
    }

    void disconnect() {
        try {
            if (conn) {
                mysql_close(conn);
                conn = NULL;
            }
        } catch (const MySQLException& e) {
            log(LogLevel::ERROR, "Disconnect Error : ", std::string(e.what()));
        }
    }
};

/* ws->getUserData returns one of these */
struct PerSocketData {
    std::string key;
    std::string uid;
    std::string metadata;

    /**
     * true - sending allowed
     * false - sending not allowed
     */
    bool sendingAllowed = true;
};

/**
 * Plaintext HTTP/WS transport.
 *
 * The server speaks plain ws:// (no TLS). TLS is terminated upstream by a load
 * balancer / reverse proxy, so there is zero per-connection TLS handshake cost
 * in the app itself.
 */
using SLApp = uWS::App; // plaintext (non-TLS) uWebSockets app
using SLWebSocket = uWS::WebSocket<false, true, PerSocketData>;

/** uWebSocket worker runs in a separate thread */
struct worker_t {
    void work();

    /* uWebSocket worker listens on separate port, or share the same port (works on Linux). */
    struct us_listen_socket_t* listen_socket_;

    /* Every thread has its own Loop, and uWS::Loop::get() returns the Loop for current thread.*/
    struct uWS::Loop* loop_;

    /** Every thread has it's own db_handler */
    std::shared_ptr<MySQLConnectionHandler> db_handler;

    /* Need to capture the uWS::App object (instance). */
    std::shared_ptr<SLApp> app_;

    /* Thread object for uWebSocket worker */
    std::shared_ptr<std::thread> thread_;
};

MDB_env* env;

/** Single shared LMDB database handle, opened once in init_env and reused for the
 *  lifetime of the process. LMDB DBI handles are meant to be opened once and shared;
 *  opening/closing one inside every transaction takes a lock and is wasteful. */
MDB_dbi g_dbi;

/** Mutexes for thread-safety */
std::mutex write_mutex;
std::mutex rateLimitMutex;
std::mutex write_worker_mutex;

/** webhooks */
enum class Webhooks : uint8_t {
    /** Message-related events */
    ON_MESSAGE = 1 << 1, /** value 2 */

    /** Connection verification events */
    ON_VERIFICATION_REQUEST = 1 << 2, /** value 4 */

    /** Connection open events */
    ON_SUBSCRIBE = 1 << 3, /** value 8 */

    /** Connection close events */
    ON_UNSUBSCRIBE = 1 << 4, /** value 16 */

    /** Room occupancy events */
    ON_ROOM_OCCUPIED = 1 << 5, /** value 32 */

    /** Room vacancy events */
    ON_ROOM_VACATED = 1 << 6 /** value 64 */
};

/** Rooms */
enum class Rooms : uint8_t {
    PUBLIC = 0,
    PRIVATE = 1,
    PUBLIC_STATE = 2,
    PRIVATE_STATE = 3,
    PUBLIC_CACHE = 4,
    PRIVATE_CACHE = 5,
    PUBLIC_STATE_CACHE = 6,
    PRIVATE_STATE_CACHE = 7
};

/**
 * Derive the room type from a room id's prefix. Returns 255 when the prefix is
 * not a recognized room type. Longer/more-specific prefixes are checked first.
 * (Previously this ladder was copy-pasted in the subscribe/unsubscribe/ban handlers.)
 */
inline uint8_t parseRoomType(const std::string& rid) {
    if (rid.rfind("pub-state-cache-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE);
    if (rid.rfind("pri-state-cache-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE);
    if (rid.rfind("pub-cache-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PUBLIC_CACHE);
    if (rid.rfind("pri-cache-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PRIVATE_CACHE);
    if (rid.rfind("pub-state-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PUBLIC_STATE);
    if (rid.rfind("pri-state-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PRIVATE_STATE);
    if (rid.rfind("pub-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PUBLIC);
    if (rid.rfind("pri-", 0) == 0)
        return static_cast<uint8_t>(Rooms::PRIVATE);
    return 255;
}

/** stores data for websocket and its worker for later use */
struct WebSocketData {
    SLWebSocket* ws;
    worker_t* worker;
};

/** Global atomic variables and data structures (all thread safe) */
/** these variables mainly stores the metrics */
std::atomic<int> globalConnectionCounter(0);
std::atomic<unsigned long long> globalMessagesSent{0};
std::atomic<unsigned long long> totalPayloadSent{0};
std::atomic<unsigned long long> totalConnectionErrors{0};    /** Websocket connections rejected due to some error */
std::atomic<unsigned long long> totalFailedApiCalls{0};      /** API calls rejected due to 4XX or 5XX codes */
std::atomic<unsigned long long> totalSuccessApiCalls{0};     /** API calls with 2XX code */
std::atomic<unsigned long long> totalLMDBWrites{0};          /** Total writes to the LMDB database */
std::atomic<unsigned long long> totalSuccessWebhookCalls{0}; /** Total webhook calls */
std::atomic<unsigned long long> totalFailedWebhookCalls{0};  /** Total failed webhook calls */
std::atomic<int> totalLatency{0};                            /** Total latency in milliseconds */
std::atomic<int> latencyCount(0);                            /** Number of latency measurements */
std::atomic<unsigned long long> droppedMessages{0};
std::atomic<unsigned int> messageCount(0);
std::atomic<bool> isMessagingDisabled(false);

/** All connection/room state uses TBB concurrent maps unconditionally. (These work
 *  fine single-threaded too, so the previous SingleThreaded std::unordered_map mirror
 *  and the isMultiThread branching were removed to eliminate ~1000 lines of duplicate,
 *  divergence-prone logic.) */
namespace ThreadSafe {
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> topics;
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> bannedConnections;
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> disabledConnections;
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>> uidToRoomMapping;
    tbb::concurrent_hash_map<std::string, bool> uid;
    tbb::concurrent_hash_map<std::string, WebSocketData> connections;
} // namespace ThreadSafe

/** map to store enabled webhooks and features (no need to make it thread safe) */
std::unordered_map<Webhooks, int> webhookStatus;
std::shared_mutex webhookMutex;

std::vector<worker_t> workers;

/** Thread local variables */
thread_local boost::asio::io_context io_context;
thread_local boost::asio::ssl::context ssl_context(boost::asio::ssl::context::sslv23);
thread_local std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> ssl_socket = nullptr;
thread_local double localEma = 0.0;
thread_local std::chrono::time_point<std::chrono::high_resolution_clock> threadTimestamp =
    std::chrono::high_resolution_clock::now();
static thread_local simdjson::ondemand::parser parser;

/** Sending Constants */
constexpr const char* ROOM_NAME_INVALID = "ROOM_NAME_INVALID";
constexpr const char* API_KEY_INVALID = "API_KEY_INVALID";
constexpr const char* CONNECTION_LIMIT_EXCEEDED = "CONNECTION_LIMIT_EXCEEDED";
constexpr const char* SOMEONE_JOINED_THE_ROOM = "SOMEONE_JOINED_THE_ROOM";
constexpr const char* CONNECTED_TO_ROOM = "CONNECTED_TO_ROOM";
constexpr const char* SOMEONE_LEFT_THE_ROOM = "SOMEONE_LEFT_THE_ROOM";
constexpr const char* YOU_ARE_RATE_LIMITED = "YOU_ARE_RATE_LIMITED";
constexpr const char* RATE_LIMIT_LIFTED = "RATE_LIMIT_LIFTED";
constexpr const char* BROADCAST = "SOCKETLINK_BROADCAST";
constexpr const char* YOU_HAVE_BEEN_BANNED = "YOU_HAVE_BEEN_BANNED";

/** HMAC-SHA256 Constants */
constexpr int HMAC_SHA256_DIGEST_LENGTH = 32; /**< SHA-256 produces a 32-byte (256-bit) output */

/** smoothing factor */
constexpr double alpha = 0.05;

using json = nlohmann::json;

/** Computes the HMAC-SHA256 of `data` under `key` into the 32-byte `output`. */
void hmac_sha256(const char* key, size_t key_len, const char* data, size_t data_len,
                 unsigned char output[HMAC_SHA256_DIGEST_LENGTH]) {
    HMAC_CTX* ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), nullptr);
    HMAC_Update(ctx, (unsigned char*)data, data_len);

    unsigned int out_len = 0;
    HMAC_Final(ctx, output, &out_len);

    HMAC_CTX_free(ctx);
}

/** Converts binary data to a lowercase hex string. */
std::string to_hex(const unsigned char* data, size_t len) {
    static const char hex_digits[] = "0123456789abcdef";

    std::string hex(len * 2, ' ');
    for (size_t i = 0; i < len; ++i) {
        hex[2 * i] = hex_digits[(data[i] >> 4) & 0xF];
        hex[2 * i + 1] = hex_digits[data[i] & 0xF];
    }

    return hex;
}

/**
 * Appends `s` to `out` as the CONTENTS of a JSON string (without surrounding quotes),
 * escaping per RFC 8259. All server envelopes and webhook payloads are built by
 * concatenating raw strings, so any user-controlled field (message, rid, uid, metadata)
 * containing a '"', '\\', or control character would otherwise break out of its JSON
 * string and corrupt the envelope (or inject fields). This makes that impossible.
 */
void appendJsonEscaped(std::string& out, std::string_view s) {
    static const char hex_digits[] = "0123456789abcdef";
    for (unsigned char c : s) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20) {
                    /** Other control characters must be escaped as \u00XX */
                    out += "\\u00";
                    out += hex_digits[(c >> 4) & 0xF];
                    out += hex_digits[c & 0xF];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
}

/** Convenience wrapper returning the JSON-escaped contents of `s` (no surrounding quotes). */
std::string jsonEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    appendJsonEscaped(out, s);
    return out;
}

/** Fetch the current UTC time in SQL-compatible format. */
std::string getCurrentSQLTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    /** gmtime_r (not gmtime) because gmtime returns a shared static buffer and is not thread-safe. */
    std::tm tm;
    gmtime_r(&now_c, &tm);

    char buffer[20]; /** 'YYYY-MM-DD HH:MM:SS' format */

    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);

    return std::string(buffer);
}

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
void write_worker(const std::string& room_id, const std::string& message_content, bool needsCommit = false) {
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

/** Decode a bitmask into the webhook-status map (1 = active, 0 = inactive). */
void populateWebhookStatus(uint8_t bitmask) {
    std::unique_lock<std::shared_mutex> lock(webhookMutex);

    for (uint8_t i = 0; i < 6; ++i) {
        Webhooks webhook = static_cast<Webhooks>(static_cast<uint8_t>(1) << i);
        webhookStatus[webhook] = (bitmask & (static_cast<uint8_t>(1) << i)) ? 1 : 0;
    }
}

/** read webhooks, thread safe */
int getWebhookStatus(Webhooks webhook) {
    std::shared_lock<std::shared_mutex> lock(webhookMutex);

    auto it = webhookStatus.find(webhook);
    return (it != webhookStatus.end()) ? it->second : 0;
}

void populateFeatureStatus(uint32_t bitmask) {
    std::unique_lock<std::shared_mutex> lock(featureMutex);

    for (uint32_t i = 0; i < 1; ++i) {
        Features feature = static_cast<Features>(1 << i);
        featureStatus[feature] = (bitmask & (1 << i)) ? 1 : 0;
    }
}

/** Synchronously send an HTTPS POST webhook on the CALLING thread. This blocks on
 *  TCP connect / SSL handshake / write, so it must NOT be called directly from a
 *  uWS event-loop thread for fire-and-forget events — use the
 *  sendHTTPSPOSTRequestFireAndForget wrapper, which offloads to a dispatcher thread.
 *  The synchronous path is used directly only when a status code is needed
 *  (waitForResponse == true, e.g. private-room verification). */
static int sendWebhookBlocking(const std::string& baseURL, const std::string& path, const std::string& body,
                               const std::map<std::string, std::string>& headers, bool waitForResponse) {
    for (int attempt = 0; attempt < 2; ++attempt) {
        try {
            /** Disable SSL certificate verification if needed. 
             *  This is insecure and should only be used for testing purposes. */
            if (UserData::getInstance().webhookIP.empty()) {
                /** DNS is not resolved, returning */
                return 0;
            }

            ssl_context.set_verify_mode(boost::asio::ssl::verify_none);

            if (!ssl_socket || !ssl_socket->lowest_layer().is_open()) {
                ssl_socket =
                    std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(io_context, ssl_context);

                constexpr int webhookPort = 443;
                boost::asio::ip::tcp::endpoint endpoint(
                    boost::asio::ip::make_address(UserData::getInstance().webhookIP), webhookPort);

                ssl_socket->lowest_layer().connect(endpoint);

                boost::asio::socket_base::keep_alive keepAliveOption(true);
                ssl_socket->lowest_layer().set_option(keepAliveOption);

                ssl_socket->handshake(boost::asio::ssl::stream_base::client);
            }

            /** TCP_NODELAY to minimize latency */
            boost::asio::ip::tcp::no_delay no_delay_option(true);
            ssl_socket->lowest_layer().set_option(no_delay_option);

            boost::asio::streambuf request_buffer;
            std::ostream request_stream(&request_buffer);

            if (UserData::getInstance().webhookSecret.length() > 0) {
                unsigned char hmac_result[HMAC_SHA256_DIGEST_LENGTH];
                hmac_sha256(UserData::getInstance().webhookSecret.c_str(),
                            UserData::getInstance().webhookSecret.length(), body.c_str(), body.length(), hmac_result);

                request_stream << "POST " << path << " HTTP/1.1\r\n"
                               << "Host: " << baseURL << "\r\n"
                               << "Connection: keep-alive\r\n"
                               << "Content-Type: application/json\r\n"
                               << "X-HMAC-Signature: " << to_hex(hmac_result, HMAC_SHA256_DIGEST_LENGTH) << "\r\n";
            } else {
                request_stream << "POST " << path << " HTTP/1.1\r\n"
                               << "Host: " << baseURL << "\r\n"
                               << "Connection: keep-alive\r\n"
                               << "Content-Type: application/json\r\n";
            }

            for (const auto& header : headers) {
                request_stream << header.first << ": " << header.second << "\r\n";
            }

            request_stream << "Content-Length: " << body.size() << "\r\n"
                           << "\r\n";

            boost::asio::write(*ssl_socket, request_buffer);

            boost::asio::write(*ssl_socket, boost::asio::buffer(body));

            if (waitForResponse) {
                boost::asio::streambuf response_buffer;
                boost::system::error_code ec;

                boost::asio::read_until(*ssl_socket, response_buffer, "\r\n\r\n", ec);

                if (!ec) {
                    std::istream response_stream(&response_buffer);
                    std::string status_line;

                    std::getline(response_stream, status_line);

                    if (status_line.empty()) {
                        log(LogLevel::INFO, "Empty response line!");
                        return 0;
                    }

                    /** parse: HTTP version, status code, status message */
                    std::istringstream status_stream(status_line);
                    std::string http_version;
                    unsigned int status_code = 0; /* 0 if the status line fails to parse */
                    std::string status_message;

                    status_stream >> http_version >> status_code;
                    std::getline(status_stream, status_message);

                    if (!status_message.empty() && status_message.front() == ' ') {
                        status_message.erase(0, 1);
                    }

                    totalSuccessWebhookCalls.fetch_add(1, std::memory_order_relaxed);

                    return status_code;
                } else {
                    log(LogLevel::ERROR, "Error reading response : ", ec.message());
                    return 0;
                }
            }

            totalSuccessWebhookCalls.fetch_add(1, std::memory_order_relaxed);

            break;
        } catch (const boost::system::system_error& e) {
            log(LogLevel::ERROR, "Error in sendHTTPSPOSTRequestFireAndForget : ", e.what());

            ssl_socket = nullptr;

            /** retry only once on failure */
            if (attempt == 1) {
                totalFailedWebhookCalls.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
    }

    return 0;
}

/**
 * Background dispatcher for fire-and-forget webhooks.
 *
 * Previously every fire-and-forget webhook was sent synchronously from inside a
 * uWS event-loop handler, which blocked that worker's entire reactor (all of its
 * connections) on TCP connect / SSL handshake / write. This dispatcher moves that
 * blocking I/O onto a dedicated thread: event-loop handlers only enqueue a job and
 * return immediately.
 *
 * The dispatcher thread owns its own thread-local SSL socket (see sendWebhookBlocking),
 * so it reuses a single persistent keep-alive connection to the customer's endpoint.
 * The queue is bounded; if the customer's endpoint is slow/down, the oldest pending
 * webhooks are dropped rather than growing memory without limit.
 */
class WebhookDispatcher {
public:
    static WebhookDispatcher& getInstance() {
        static WebhookDispatcher instance;
        return instance;
    }

    /** Enqueue a fire-and-forget webhook. Non-blocking; safe to call from event-loop threads. */
    void enqueue(std::string baseURL, std::string path, std::string body,
                 std::map<std::string, std::string> headers = {}) {
        bool droppedOne = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            /** Bound the queue to protect memory when the endpoint is slow or unreachable */
            if (queue_.size() >= maxQueueSize_) {
                queue_.pop_front();
                droppedWebhookCalls_.fetch_add(1, std::memory_order_relaxed);
                droppedOne = true;
            }
            queue_.push_back(Job{std::move(baseURL), std::move(path), std::move(body), std::move(headers)});
        }
        cv_.notify_one();

        /** webhook endpoint can't keep up — warn, but rate-limited (once per 10k drops) */
        if (droppedOne) {
            unsigned long long d = droppedWebhookCalls_.load(std::memory_order_relaxed);
            if (d == 1 || d % 10000 == 0) {
                log(LogLevel::WARN, "Webhook queue full: dropping oldest events (total dropped: ", d, ")");
            }
        }
    }

    unsigned long long droppedCount() const { return droppedWebhookCalls_.load(std::memory_order_relaxed); }

    WebhookDispatcher(const WebhookDispatcher&) = delete;
    WebhookDispatcher& operator=(const WebhookDispatcher&) = delete;

private:
    struct Job {
        std::string baseURL;
        std::string path;
        std::string body;
        std::map<std::string, std::string> headers;
    };

    WebhookDispatcher() : worker_([this]() { run(); }) {}

    ~WebhookDispatcher() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
        cv_.notify_all();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    void run() {
        while (true) {
            Job job;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this]() { return !queue_.empty() || !running_; });
                if (!running_ && queue_.empty()) {
                    return;
                }
                job = std::move(queue_.front());
                queue_.pop_front();
            }
            /** Blocking send happens on this dedicated thread, never on an event loop */
            sendWebhookBlocking(job.baseURL, job.path, job.body, job.headers, false);
        }
    }

    std::deque<Job> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool running_ = true;
    std::atomic<unsigned long long> droppedWebhookCalls_{0};
    static constexpr size_t maxQueueSize_ = 100000;
    std::thread worker_;
};

/**
 * @brief Dispatch an HTTPS POST webhook.
 *
 * For fire-and-forget events (waitForResponse == false) the request is handed to a
 * background dispatcher thread and this returns immediately, so the calling event loop
 * never blocks on webhook I/O. When a status code is required (waitForResponse == true,
 * e.g. private-room verification) the request is sent synchronously on the calling thread
 * and the HTTP status is returned.
 */
int sendHTTPSPOSTRequestFireAndForget(const std::string& baseURL, const std::string& path, const std::string& body,
                                      const std::map<std::string, std::string>& headers = {},
                                      bool waitForResponse = false) {
    if (waitForResponse) {
        return sendWebhookBlocking(baseURL, path, body, headers, true);
    }

    WebhookDispatcher::getInstance().enqueue(baseURL, path, body, headers);
    return 0;
}

/**
 * Resolves the IPv4 address for `hostname` and stores it in the config snapshot
 * `ud` being built (ud.webhookIP).
 */
void resolveAndStoreIPAddress(UserData& ud, const std::string& hostname) {
    struct addrinfo hints, *res = nullptr;
    char ipAddress[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (status != 0) {
        log(LogLevel::ERROR, "getaddrinfo error : ", gai_strerror(status));
        return;
    }

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, sizeof(ipAddress));

    ud.webhookIP = ipAddress;

    freeaddrinfo(res);
}

int populateUserData(std::string data) {
    nlohmann::json parsedJson = nlohmann::json::parse(data);
    int needsDBUpdate = 0;

    /** Serialize concurrent writers, then build the new config on a private copy of
     *  the current snapshot and publish it atomically at the end. Readers keep seeing
     *  the old immutable snapshot until publish(), so there is no read/write race. */
    std::lock_guard<std::mutex> writeLock(configWriteMutex);
    UserData userData = UserData::getInstance();

    if (parsedJson.contains("client_api_key") && !parsedJson["client_api_key"].is_null()) {
        userData.clientApiKey = parsedJson["client_api_key"].get<std::string>();
    }

    if (parsedJson.contains("admin_api_key") && !parsedJson["admin_api_key"].is_null()) {
        userData.adminApiKey = parsedJson["admin_api_key"].get<std::string>();
    }

    if (parsedJson.contains("connections") && !parsedJson["connections"].is_null()) {
        userData.connections = parsedJson["connections"].get<int>();
    }

    if (parsedJson.contains("msg_size_allowed_in_bytes") && !parsedJson["msg_size_allowed_in_bytes"].is_null()) {
        userData.msgSizeAllowedInBytes = parsedJson["msg_size_allowed_in_bytes"].get<unsigned int>();
    }

    if (parsedJson.contains("webhooks") && !parsedJson["webhooks"].is_null()) {
        userData.webhooks = parsedJson["webhooks"].get<uint8_t>();

        populateWebhookStatus(userData.webhooks);
    }

    if (parsedJson.contains("features") && !parsedJson["features"].is_null()) {
        userData.features = parsedJson["features"].get<uint32_t>();
    }

    if (parsedJson.contains("webhook_base_url") && !parsedJson["webhook_base_url"].is_null()) {
        userData.webHookBaseUrl = parsedJson["webhook_base_url"].get<std::string>();

        resolveAndStoreIPAddress(userData, userData.webHookBaseUrl);
    }

    if (parsedJson.contains("webhook_path") && !parsedJson["webhook_path"].is_null()) {
        userData.webhookPath = parsedJson["webhook_path"].get<std::string>();
    }

    if (parsedJson.contains("webhook_secret") && !parsedJson["webhook_secret"].is_null()) {
        userData.webhookSecret = parsedJson["webhook_secret"].get<std::string>();
    }

    if (parsedJson.contains("max_storage_allowed_in_gb") && !parsedJson["max_storage_allowed_in_gb"].is_null()) {
        userData.lmdbDatabaseSizeInBytes =
            parsedJson["max_storage_allowed_in_gb"].get<unsigned long long>() * 1024ULL * 1024 * 1024;
    }

    if (parsedJson.contains("lmdb_commit_batch_size") && !parsedJson["lmdb_commit_batch_size"].is_null()) {
        userData.lmdbCommitBatchSize = parsedJson["lmdb_commit_batch_size"].get<int>();
    }

    if (parsedJson.contains("db_commit_batch_size") && !parsedJson["db_commit_batch_size"].is_null()) {
        userData.mysqlDBCommitBatchSize = parsedJson["db_commit_batch_size"].get<int>();
    }

    if (parsedJson.contains("idle_timeout_in_seconds") && !parsedJson["idle_timeout_in_seconds"].is_null()) {
        unsigned short idleTimeoutInSeconds = parsedJson["idle_timeout_in_seconds"].get<unsigned short>();
        if (userData.idleTimeoutInSeconds == 60 && idleTimeoutInSeconds != userData.idleTimeoutInSeconds) {
            userData.idleTimeoutInSeconds = idleTimeoutInSeconds;
        } else {
            userData.idleTimeoutInSeconds = idleTimeoutInSeconds;
            needsDBUpdate = 2;
        }
    }

    if (parsedJson.contains("max_lifetime_in_minutes") && !parsedJson["max_lifetime_in_minutes"].is_null()) {
        unsigned short maxLifetimeInMinutes = parsedJson["max_lifetime_in_minutes"].get<unsigned short>();
        if (userData.maxLifetimeInMinutes == 0 && maxLifetimeInMinutes != userData.maxLifetimeInMinutes) {
            userData.maxLifetimeInMinutes = maxLifetimeInMinutes;
        } else {
            userData.maxLifetimeInMinutes = maxLifetimeInMinutes;
            needsDBUpdate = 2;
        }
    }

    if (parsedJson.contains("max_backpressure_in_bytes") && !parsedJson["max_backpressure_in_bytes"].is_null()) {
        userData.maxBackpressureInBytes = parsedJson["max_backpressure_in_bytes"].get<unsigned int>();
    }

    populateFeatureStatus(userData.features);

    int is_sql_integration_enabled = 0;

    if (parsedJson.contains("is_sql_integration_enabled") && !parsedJson["is_sql_integration_enabled"].is_null()) {
        if (parsedJson["is_sql_integration_enabled"].get<bool>()) {
            is_sql_integration_enabled = 1;
        } else {
            is_sql_integration_enabled = -1;
        }
    }

    std::string dbHost = "";
    std::string dbUser = "";
    std::string dbPassword = "";
    std::string dbName = "";
    int dbPort = 0;

    if (parsedJson.contains("db_host") && !parsedJson["db_host"].is_null()) {
        dbHost = parsedJson["db_host"].get<std::string>();
    }
    if (parsedJson.contains("db_user") && !parsedJson["db_user"].is_null()) {
        dbUser = parsedJson["db_user"].get<std::string>();
    }
    if (parsedJson.contains("db_password") && !parsedJson["db_password"].is_null()) {
        dbPassword = parsedJson["db_password"].get<std::string>();
    }
    if (parsedJson.contains("db_name") && !parsedJson["db_name"].is_null()) {
        dbName = parsedJson["db_name"].get<std::string>();
    }
    if (parsedJson.contains("db_port") && !parsedJson["db_port"].is_null()) {
        dbPort = parsedJson["db_port"].get<int>();
    }

    if (dbHost.length() > 0 && dbUser.length() > 0 && dbPassword.length() > 0 && dbName.length() > 0 && dbPort != 0) {
        if (userData.dbHost != dbHost || userData.dbUser != dbUser || userData.dbPassword != dbPassword ||
            userData.dbName != dbName || userData.dbPort != dbPort) {
            userData.dbHost = dbHost;
            userData.dbUser = dbUser;
            userData.dbPassword = dbPassword;
            userData.dbName = dbName;
            userData.dbPort = dbPort;
        }
    }

    if (is_sql_integration_enabled == 1) {
        std::unique_lock<std::shared_mutex> lock(featureMutex);
        featureStatus[Features::ENABLE_MYSQL_INTEGRATION] = 1;
        needsDBUpdate = 1;
    } else if (is_sql_integration_enabled == -1) {
        std::unique_lock<std::shared_mutex> lock(featureMutex);
        featureStatus[Features::ENABLE_MYSQL_INTEGRATION] = 0;
        needsDBUpdate = -1;
    }

    /** Publish the fully-built config snapshot atomically (readers switch over on
     *  their next getInstance()). The previous snapshot is intentionally leaked. */
    UserData::publish(new UserData(std::move(userData)));

    return needsDBUpdate;
}

/** unsubscribe from the current room and do some cleanup */
void closeConnection(SLWebSocket* ws, worker_t* worker, std::string rid, std::string uid, uint8_t roomType,
                     bool isClosed = false) {
    if (isClosed == false) {
        /** remove the RID from the uid -> room mapping */
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

    /** remove the user from the room in topics */
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor outer_accessor;

    int size = 0;

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

    log(LogLevel::DEBUG, "Unsubscribed: uid=", uid, " rid=", rid, " (room size ", size, ")");

    /** Unsubscribe on the correct thread */
    auto unsubscribe_fn = [ws, rid]() { ws->unsubscribe(rid); };
    if (worker->thread_->get_id() != std::this_thread::get_id()) {
        worker->loop_->defer(unsubscribe_fn);
    } else {
        unsubscribe_fn();
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

        /** subscribe on the thread that owns the ws instance */
        if (workerThreadId == currentThreadId) {
            ws->subscribe(rid);
        } else {
            worker->loop_->defer([ws, rid]() { ws->subscribe(rid); });
        }

        int size = 0;

        {
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

        {
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

/** calculate latency for each thread */
void update_ema(double newLatency) {
    localEma = alpha * newLatency + (1 - alpha) * localEma;
}


/* uWebSocket worker thread function. */
void worker_t::work() {
    /** Fixed plaintext HTTP/WS listen port. */
    const int listenPort = SL_LISTEN_PORT;

    /* Every thread has its own Loop, and uWS::Loop::get() returns the Loop for current thread.*/
    loop_ = uWS::Loop::get();

    /* uWS::App object / instance is used in uWS::Loop::defer(lambda_function).
   * Plaintext: TLS is terminated upstream (load balancer). No cert needed. */
    app_ = std::make_shared<SLApp>(SLApp());

    db_handler = std::make_unique<MySQLConnectionHandler>();

    /* Very simple WebSocket broadcasting echo server */
    app_->ws<PerSocketData>(
            "/*",
            {/* Settings */
             .compression = uWS::DISABLED,
             .maxPayloadLength = UserData::getInstance().msgSizeAllowedInBytes,
             .idleTimeout = UserData::getInstance().idleTimeoutInSeconds,
             .maxBackpressure = UserData::getInstance().maxBackpressureInBytes,
             .closeOnBackpressureLimit = false,
             .resetIdleTimeoutOnSend = true,
             .sendPingsAutomatically = true,
             .maxLifetime = UserData::getInstance().maxLifetimeInMinutes,

             /* Handlers */
             .upgrade =
                 [](auto* res, auto* req, auto* context) {
                     struct UpgradeData {
                         std::string secWebSocketKey;
                         std::string secWebSocketProtocol;
                         std::string secWebSocketExtensions;
                         std::string key;
                         std::string uid;
                         std::string metadata;
                         struct us_socket_context_t* context;
                         decltype(res) httpRes;
                         bool aborted = false;
                     };

                     /** Owned for the (synchronous) lifetime of this handler; freed automatically
         *  on every return path. Previously heap-allocated with `new` and never
         *  deleted -> one leak per connection attempt. */
                     auto upgradeData = std::unique_ptr<UpgradeData>(new UpgradeData{
                         std::string(req->getHeader("sec-websocket-key")),
                         std::string(req->getHeader("sec-websocket-protocol")),
                         std::string(req->getHeader("sec-websocket-extensions")),
                         std::string(req->getHeader("api-key")),
                         std::string(req->getHeader("uid").data() ? req->getHeader("uid") : ""),
                         std::string(req->getHeader("metadata").data() ? req->getHeader("metadata") : ""), context,
                         res});

                     res->onAborted([ud = upgradeData.get()]() { ud->aborted = true; });

                     if (upgradeData->uid.empty() || upgradeData->uid.length() > 4096) {
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("400 Bad Request");
                             res->writeHeader("Content-Type", "application/json");
                             res->end("INVALID_UID");
                         });

                         return;
                     }

                     if (upgradeData->metadata.length() > 1024) {
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("413 Payload Too Large");
                             res->writeHeader("Content-Type", "application/json");
                             res->end("INVALID_METADATA");
                         });

                         return;
                     }

                     {
                         /** Check if the user is banned and reject the connection */
                         tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor
                             bannedAccessor;
                         if (ThreadSafe::bannedConnections.find(bannedAccessor, "global")) {
                             /** Access the inner map */
                             tbb::concurrent_hash_map<std::string, bool>& inner_map = bannedAccessor->second;

                             /** Accessor for the inner map */
                             tbb::concurrent_hash_map<std::string, bool>::accessor innerAccessor;

                             /** Check if the user UID is banned in the inner map */
                             if (inner_map.find(innerAccessor, upgradeData->uid)) {

                                 totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);
                                 log(LogLevel::DEBUG, "Connection rejected (banned): uid=", upgradeData->uid);

                                 res->cork([res]() {
                                     res->writeStatus("403 Forbidden");
                                     res->writeHeader("Content-Type", "application/json");
                                     res->end("CONNECTION_BANNED");
                                 });

                                 return;
                             }
                         }
                     }

                     {
                         /** check if a connection is already there with the same uid (thread safe) */
                         tbb::concurrent_hash_map<std::string, bool>::const_accessor accessor;
                         if (ThreadSafe::uid.find(accessor, upgradeData->uid)) {

                             totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);
                             log(LogLevel::DEBUG, "Connection rejected (duplicate uid): uid=", upgradeData->uid);

                             res->cork([res]() { res->writeStatus("409 Conflict")->end("UID_ALREADY_EXIST"); });

                             return;
                         }
                     }

                     /** Check if API key is valid or not */
                     if (UserData::getInstance().clientApiKey != upgradeData->key) {
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);
                         log(LogLevel::WARN, "Connection rejected (invalid client api key): uid=", upgradeData->uid);

                         res->cork([res]() { res->writeStatus("401 Unauthorized")->end("INVALID_API_KEY"); });

                         return;
                     }

                     /** Reserve a connection slot atomically so the limit is a HARD cap with no
         *  overshoot. Previously the check (here) and the increment (in .open) were at
         *  different lifecycle points, so concurrent upgrades could all pass the check
         *  before any of them counted, letting the server exceed `connections`.
         *  fetch_add returns the PREVIOUS value; if we were already at the limit, give
         *  the slot back and reject. The slot is released in .close on the normal path,
         *  or in the else branch below if the request aborts before it is upgraded. */
                     if (globalConnectionCounter.fetch_add(1, std::memory_order_relaxed) >=
                         UserData::getInstance().connections) {
                         globalConnectionCounter.fetch_sub(1, std::memory_order_relaxed);
                         totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                         /** important operational signal, but rate-limited: sustained overload
             *  would otherwise emit one WARN per rejected attempt */
                         static std::atomic<unsigned long long> limitRejections{0};
                         if (limitRejections.fetch_add(1, std::memory_order_relaxed) % 1000 == 0) {
                             log(LogLevel::WARN, "Connection limit reached (", UserData::getInstance().connections,
                                 "): rejecting new connections (total rejected: ",
                                 limitRejections.load(std::memory_order_relaxed), ")");
                         }

                         res->cork([res]() {
                             res->writeStatus("503 Service Unavailable")->end("MAX_CONNECTION_LIMIT_REACHED");
                         });

                         return;
                     }

                     if (!upgradeData->aborted) {
                         upgradeData->httpRes->cork([ud = upgradeData.get()]() {
                             ud->httpRes->template upgrade<PerSocketData>(
                                 {
                                     /* We initialize PerSocketData struct here */
                                     .key = ud->key,
                                     .uid = ud->uid,
                                     .metadata = ud->metadata,
                                 },
                                 ud->secWebSocketKey, ud->secWebSocketProtocol, ud->secWebSocketExtensions,
                                 ud->context);
                         });
                     } else {
                         /** Slot was reserved above, but the request aborted before upgrading, so
             *  .open/.close will never run to release it -- release it here. */
                         globalConnectionCounter.fetch_sub(1, std::memory_order_relaxed);
                     }
                 },
             .open =
                 [this](auto* ws) {
                     WebSocketData data;
                     data.ws = ws;
                     data.worker = this;

                     std::string userId = ws->getUserData()->uid;

                     /** The connection slot was already reserved atomically in the upgrade handler
         *  (hard limit) and is released in .close; do not count again here. */

                     {
                         tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
                         bool inserted = ThreadSafe::connections.insert(conn_accessor, userId);
                         if (inserted) {
                             conn_accessor->second = std::move(data);
                         } else {
                             /** UID already exists, something went wrong */
                             ws->end();
                             return;
                         }
                     }

                     {
                         tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;
                         if (ThreadSafe::uid.insert(user_accessor, userId)) {
                             user_accessor->second = true;
                         } else {
                             /** UID already exists, something went wrong */
                             ws->end();
                             return;
                         }
                     }

                     log(LogLevel::DEBUG, "Connection open: uid=", userId, " (",
                         globalConnectionCounter.load(std::memory_order_relaxed), " total)");

                     ws->subscribe(userId);
                     ws->subscribe(BROADCAST);
                 },
             .message =
                 [this](auto* ws, std::string_view message, uWS::OpCode opCode) {
                     auto& userData = *ws->getUserData();
                     const auto& uid = userData.uid;

                     auto sendMessagingDisabled = [&]() {
                         ws->send("{\"data\":\"MESSAGING_DISABLED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                     };

                     /** checking if the message sending is disabled globally at the server level */
                     if (isMessagingDisabled.load(std::memory_order_relaxed)) {
                         sendMessagingDisabled();
                         return;
                     }

                     /** checking if the messaging is disabled for a particular connection at global level.
         *  Fast path: skip the hash lookup + bucket lock entirely when nobody is disabled
         *  (empty() reads an O(1) size counter, no hashing/locking). */
                     if (!ThreadSafe::disabledConnections.empty()) {
                         /** Check if messaging is disabled for the user */
                         tbb::concurrent_hash_map<
                             std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor outer_accessor;
                         tbb::concurrent_hash_map<std::string, bool>::const_accessor inner_accessor;

                         if (ThreadSafe::disabledConnections.find(outer_accessor, "global") &&
                             outer_accessor->second.find(inner_accessor, uid)) {
                             sendMessagingDisabled();
                             return;
                         }
                     }

                     if (ws->getUserData()->sendingAllowed) {
                         /** check if the backpressure exceeded the given limit */
                         if (ws->getBufferedAmount() > UserData::getInstance().maxBackpressureInBytes) {
                             ws->send("{\"data\":\"YOU_ARE_RATE_LIMITED\",\"source\":\"server\"}", uWS::OpCode::TEXT,
                                      true);
                             droppedMessages.fetch_add(1, std::memory_order_relaxed);
                             ws->getUserData()->sendingAllowed = false;
                         } else {
                             auto sendInvalidJson = [&]() {
                                 ws->send(R"({"data":"INVALID_JSON","source":"server"})", uWS::OpCode::TEXT, true);
                             };

                             try {
                                 simdjson::ondemand::document parsedData;

                                 /** simdjson (ondemand) reads up to SIMDJSON_PADDING bytes past the end of
                     *  the document as scratch space. The incoming `message` is a string_view
                     *  owned by uWebSockets and offers no such trailing padding, so parsing it
                     *  in place would be an out-of-bounds read. Copy it into a reused thread-local
                     *  buffer whose capacity always includes the required padding. */
                                 static thread_local std::string jsonBuffer;
                                 jsonBuffer.reserve(message.size() + simdjson::SIMDJSON_PADDING);
                                 jsonBuffer.assign(message.data(), message.size());

                                 if (auto error =
                                         parser.iterate(jsonBuffer.data(), jsonBuffer.size(), jsonBuffer.capacity())
                                             .get(parsedData);
                                     error) {
                                     sendInvalidJson();
                                     return;
                                 }

                                 /** a "timestamp" field means this is a reply to a latency probe */
                                 if (auto timeField = parsedData["timestamp"]; !timeField.error()) {
                                     int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                           std::chrono::high_resolution_clock::now() - threadTimestamp)
                                                           .count();

                                     update_ema(elapsed);

                                     return;
                                 }

                                 std::string rid;
                                 if (auto ridField = parsedData["rid"]; !ridField.error()) {
                                     rid = std::string(ridField.get_string().value());
                                 } else {
                                     sendInvalidJson();
                                     return;
                                 }

                                 std::string message;
                                 if (auto msgField = parsedData["message"]; !msgField.error()) {
                                     message = std::string(msgField.get_string().value());
                                 } else {
                                     sendInvalidJson();
                                     return;
                                 }

                                 uint8_t roomType = 255;

                                 auto sendNoSubscriptionFound = [&]() {
                                     ws->send(R"({"data":"NO_SUBSCRIPTION_FOUND","source":"server"})",
                                              uWS::OpCode::TEXT, true);
                                 };

                                 {
                                     /** the sender must already be subscribed to `rid`; fetch its room type */
                                     tbb::concurrent_hash_map<
                                         std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::const_accessor
                                         uid_to_rid_outer_accessor;

                                     if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, uid)) {
                                         auto& inner_map = uid_to_rid_outer_accessor->second;

                                         tbb::concurrent_hash_map<std::string, uint8_t>::const_accessor
                                             uid_to_rid_inner_accessor;

                                         if (!inner_map.find(uid_to_rid_inner_accessor, rid)) {
                                             sendNoSubscriptionFound();
                                             return;
                                         }

                                         roomType = uid_to_rid_inner_accessor->second;
                                     } else {
                                         sendNoSubscriptionFound();
                                         return;
                                     }
                                 }

                                 /** Fast path: skip the room-disabled lookup when nobody is disabled anywhere. */
                                 if (!ThreadSafe::disabledConnections.empty()) {
                                     tbb::concurrent_hash_map<
                                         std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor
                                         outer_accessor;
                                     tbb::concurrent_hash_map<std::string, bool>::const_accessor inner_accessor;

                                     if ((ThreadSafe::disabledConnections.find(outer_accessor, rid) &&
                                          outer_accessor->second.find(inner_accessor, uid))) {
                                         ws->send("{\"data\":\"MESSAGING_DISABLED\",\"source\":\"server\"}",
                                                  uWS::OpCode::TEXT, true);
                                         return;
                                     }
                                 }

                                 /** Build the published envelope once, escaping the user-controlled
                     *  message and room id so a quote/backslash/control char cannot break
                     *  out of the JSON string or inject fields. */
                                 auto data = std::make_shared<std::string>();
                                 data->reserve(message.size() + rid.size() + 40);
                                 *data += "{\"data\":\"";
                                 appendJsonEscaped(*data, message);
                                 *data += "\",\"source\":\"user\",\"rid\":\"";
                                 appendJsonEscaped(*data, rid);
                                 *data += "\"}";

                                 /** publish locally on this worker */
                                 ws->publish(rid, *data, opCode, true);

                                 /** Publish on every other worker's loop. The payload and room id are
                     *  shared via shared_ptr so they are not copied once per worker thread. */
                                 auto ridShared = std::make_shared<std::string>(rid);
                                 for (auto& w : ::workers) {
                                     if (std::this_thread::get_id() != w.thread_->get_id()) {
                                         w.loop_->defer([&w, data, ridShared, opCode]() {
                                             w.app_->publish(*ridShared, *data, opCode, true);
                                         });
                                     }
                                 }

                                 /** send latency message to the current websocket, random selection */
                                 auto now = std::chrono::high_resolution_clock::now();
                                 auto elapsed =
                                     std::chrono::duration_cast<std::chrono::seconds>(now - threadTimestamp).count();

                                 if (elapsed > 10) {
                                     ws->send(R"({"source":"latency"})", uWS::OpCode::TEXT, true);
                                     threadTimestamp = now;
                                 }

                                 unsigned int subscribers = app_->numSubscribers(rid);
                                 globalMessagesSent.fetch_add(static_cast<unsigned long long>(subscribers),
                                                              std::memory_order_relaxed);
                                 totalPayloadSent.fetch_add(static_cast<unsigned long long>(data->size()) *
                                                                static_cast<unsigned long long>(subscribers),
                                                            std::memory_order_relaxed);

                                 /** cache rooms persist their messages (LMDB / SQL) */
                                 if (roomType == static_cast<uint8_t>(Rooms::PUBLIC_CACHE) ||
                                     roomType == static_cast<uint8_t>(Rooms::PRIVATE_CACHE) ||
                                     roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) ||
                                     roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)) {
                                     /** store the latest message under the room id (batched; the read
                         *  endpoint forces a flush before reading) */
                                     write_worker(rid, std::string(message));
                                     totalLMDBWrites.fetch_add(1, std::memory_order_relaxed);

                                     /** SQL integration works in cache channels only */
                                     if (getFeatureStatus(Features::ENABLE_MYSQL_INTEGRATION) == 1) {
                                         db_handler->insertSingleData(getCurrentSQLTime(), std::string(message), uid,
                                                                      rid);
                                     }
                                 }

                                 if (getWebhookStatus(Webhooks::ON_MESSAGE) == 1) {
                                     std::ostringstream payload;
                                     payload << "{\"event\":\"ON_MESSAGE\", " << "\"uid\":\"" << jsonEscape(uid)
                                             << "\", " << "\"rid\":\"" << jsonEscape(rid) << "\", " << "\"message\":\""
                                             << jsonEscape(message) << "\"}";

                                     std::string body = payload.str();

                                     sendHTTPSPOSTRequestFireAndForget(UserData::getInstance().webHookBaseUrl,
                                                                       UserData::getInstance().webhookPath, body, {});
                                 }
                             } catch (const simdjson::simdjson_error& e) {
                                 sendInvalidJson();
                             }
                         }
                     } else {
                         ws->send("{\"data\":\"YOU_ARE_RATE_LIMITED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                         droppedMessages.fetch_add(1, std::memory_order_relaxed);
                     }
                 },
             .dropped =
                 [](auto* /*ws*/, std::string_view /*message*/, uWS::OpCode /*opCode*/) {
                     /** A message was dropped because this connection is over its backpressure
         *  limit. Do NOT ws->send() a notification here: the send buffer is already
         *  full, so that send would itself be dropped and re-invoke this handler
         *  synchronously, recursing until the stack overflows and the server crashes
         *  under sustained backpressure. Just count the drop; the client learns it is
         *  rate-limited via the YOU_ARE_RATE_LIMITED path when it next sends, and via
         *  RATE_LIMIT_LIFTED (in .drain) once its buffer drains. */
                     droppedMessages.fetch_add(1, std::memory_order_relaxed);
                 },
             .drain =
                 [](auto* ws) {
                     /** only notify clients that were actually rate-limited */
                     if (!ws->getUserData()->sendingAllowed &&
                         ws->getBufferedAmount() < (UserData::getInstance().maxBackpressureInBytes / 2)) {
                         ws->getUserData()->sendingAllowed = true;
                         ws->send("{\"data\":\"RATE_LIMIT_LIFTED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                     }
                 },
             .close =
                 [this](auto* ws, int /* code */, std::string_view /* message */) {
                     std::string userId = ws->getUserData()->uid;

                     /** release the reserved connection slot (reserved in the upgrade handler) */
                     globalConnectionCounter.fetch_sub(1, std::memory_order_relaxed);

                     log(LogLevel::DEBUG, "Connection closed: uid=", userId, " (",
                         globalConnectionCounter.load(std::memory_order_relaxed), " remaining)");

                     {
                         tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
                         if (ThreadSafe::connections.find(conn_accessor, userId)) {
                             ThreadSafe::connections.erase(conn_accessor);
                         }
                     }

                     {
                         tbb::concurrent_hash_map<std::string, bool>::accessor uid_accessor;
                         if (ThreadSafe::uid.find(uid_accessor, userId)) {
                             ThreadSafe::uid.erase(uid_accessor);
                         }
                     }

                     ws->unsubscribe(userId);
                     ws->unsubscribe(BROADCAST);

                     /** close every room subscription for this uid, then drop the uid mapping */
                     {
                         tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor
                             outer_accessor;

                         if (ThreadSafe::uidToRoomMapping.find(outer_accessor, userId)) {
                             auto& inner_map = outer_accessor->second;

                             for (auto& entry : inner_map) {
                                 closeConnection(ws, this, entry.first, userId, entry.second, true);
                             }

                             ThreadSafe::uidToRoomMapping.erase(outer_accessor);
                         }
                     }
                 }})
        .get("/api/v1/metrics",
             [](auto* res, auto* req) {
                 /** fetch all the server metrics */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     if (req->getHeader("api-key") != UserData::getInstance().adminApiKey) {
                         log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("401 Unauthorized");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"connections": )" +
                                      std::to_string(globalConnectionCounter.load(std::memory_order_relaxed)) +
                                      R"(,"messages_sent": )" +
                                      std::to_string(globalMessagesSent.load(std::memory_order_relaxed)) +
                                      R"(,"total_payload_sent": )" +
                                      std::to_string(totalPayloadSent.load(std::memory_order_relaxed)) +
                                      R"(,"total_failed_api_calls": )" +
                                      std::to_string(totalFailedApiCalls.load(std::memory_order_relaxed)) +
                                      R"(,"total_success_api_calls": )" +
                                      std::to_string(totalSuccessApiCalls.load(std::memory_order_relaxed)) +
                                      R"(,"total_failed_connection_attempts": )" +
                                      std::to_string(totalConnectionErrors.load(std::memory_order_relaxed)) +
                                      R"(,"total_mysql_db_batch_writes": )" +
                                      std::to_string(totalMysqlDBWrites.load(std::memory_order_relaxed)) +
                                      R"(,"total_local_db_writes": )" +
                                      std::to_string(totalLMDBWrites.load(std::memory_order_relaxed)) +
                                      R"(,"total_success_webhook_calls": )" +
                                      std::to_string(totalSuccessWebhookCalls.load(std::memory_order_relaxed)) +
                                      R"(,"total_failed_webhook_calls": )" +
                                      std::to_string(totalFailedWebhookCalls.load(std::memory_order_relaxed)) +
                                      R"(,"average_latency": )" + std::to_string(localEma) +
                                      R"(,"dropped_messages": )" +
                                      std::to_string(droppedMessages.load(std::memory_order_relaxed)) + R"(})");
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .post("/api/v1/invalidate",
              [](auto* res, auto* req) {
                  /** update the metadata used by the server */

                  auto isAborted = std::make_shared<bool>(false);

                  res->onAborted([isAborted]() {
                      *isAborted = true;
                      totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                  });

                  try {
                      std::string_view apiKey = req->getHeader("api-key");

                      /** Admin-key auth (self-hosted: no master shared-secret signature) */
                      if (apiKey != UserData::getInstance().adminApiKey) {
                          log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                          if (!*isAborted) {
                              totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                              res->cork([res]() {
                                  res->writeStatus("401 Unauthorized");
                                  res->writeHeader("Content-Type", "application/json");
                                  res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                              });
                          }

                          return;
                      }

                      std::string body;

                      body.reserve(1024);

                      res->onData(
                          [res, req, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
                              body.append(data.data(), data.length());

                              if (last) {
                                  try {
                                      /** Apply the new config (admin-key already verified above) */
                                      int action = populateUserData(body);

                                      if (action == 1) {
                                          /** check if the connection parameters are changed */
                                          std::for_each(::workers.begin(), ::workers.end(), [](worker_t& w) {
                                              /** Defer the message publishing to the worker's loop */
                                              w.loop_->defer([&w]() { w.db_handler->manualCreateConnection(); });
                                          });
                                      } else if (action == -1) {
                                          std::for_each(::workers.begin(), ::workers.end(), [](worker_t& w) {
                                              /** Defer the message publishing to the worker's loop */
                                              w.loop_->defer([&w]() {
                                                  w.db_handler->flushRemainingData();
                                                  w.db_handler->disconnect();
                                              });
                                          });
                                      }

                                      log(LogLevel::INFO, "Config updated via /api/v1/invalidate");

                                      if (!*isAborted) {
                                          totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                          res->cork([res]() {
                                              res->writeStatus("200 OK");
                                              res->writeHeader("Content-Type", "application/json");
                                              res->end(R"({"message": "Metadata invalidated successfully!"})");
                                          });
                                      }

                                      if (action == 2) {
                                          log(LogLevel::INFO, "idle_timeout/max_lifetime changed: exiting in 1s so the "
                                                              "process manager restarts with the new socket settings");
                                          std::thread([]() {
                                              std::this_thread::sleep_for(std::chrono::seconds(1));
                                              std::exit(0);
                                          }).detach();
                                      }
                                  } catch (std::exception& e) {
                                      if (!*isAborted) {
                                          totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                          res->cork([res]() {
                                              res->writeStatus("400 Bad Request");
                                              res->writeHeader("Content-Type", "application/json");
                                              res->end(R"({"message": "Invalid JSON format!"})");
                                          });
                                      }
                                  }
                              }
                          });
                  } catch (std::exception& e) {
                      if (!*isAborted) {
                          totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                          res->cork([res]() {
                              res->writeStatus("500 Internal Server Error");
                              res->writeHeader("Content-Type", "application/json");
                              res->end(R"({"message": "Internal server error!"})");
                          });
                      }
                  }
              })
        .get("/api/v1/mysql/sync",
             [](auto* res, auto* req) {
                 /** sync all the data in the buffers to integrated mysql server */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     if (req->getHeader("api-key") != UserData::getInstance().adminApiKey) {
                         log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("401 Unauthorized");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     if (getFeatureStatus(Features::ENABLE_MYSQL_INTEGRATION) == 0) {
                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("403 Forbidden");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "MySQL integration is disabled!"})");
                             });
                         }

                         return;
                     }

                     std::for_each(::workers.begin(), ::workers.end(), [](worker_t& w) {
                         /** Defer the message publishing to the worker's loop */
                         w.loop_->defer([&w]() { w.db_handler->flushRemainingData(); });
                     });

                     log(LogLevel::INFO, "Admin API: MySQL flush requested via /api/v1/mysql/sync");

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "MySQL data synced successfully!"})");
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .get("/api/v1/rooms/users/all",
             [this](auto* res, auto* req) {
                 /** fetch all the rooms present on the server */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     if (req->getHeader("api-key") != UserData::getInstance().adminApiKey) {
                         log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("401 Unauthorized");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     nlohmann::json data = nlohmann::json::array();

                     for (const auto& [rid, users] : ThreadSafe::topics) {
                         nlohmann::json roomData;
                         roomData["rid"] = rid;

                         std::vector<std::string> userKeys;

                         for (const auto& [uid, _] : users) {
                             userKeys.push_back(uid);
                         }

                         roomData["uid"] = std::move(userKeys);

                         data.push_back(std::move(roomData));
                     }

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res, data]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(data.dump());
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .get("/api/v1/users/orphan",
             [this](auto* res, auto* req) {
                 /** fetch all the rooms present on the server */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     if (req->getHeader("api-key") != UserData::getInstance().adminApiKey) {
                         log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("401 Unauthorized");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     std::vector<std::string> orphanUids;

                     for (auto it = ThreadSafe::uid.begin(); it != ThreadSafe::uid.end(); ++it) {
                         if (it->second) {
                             orphanUids.push_back(it->first);
                         }
                     }

                     nlohmann::json data;
                     data["uid"] = orphanUids;

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res, data]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(data.dump());
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .post(
            "/api/v1/rooms/users",
            [this](auto* res, auto* req) {
                /** get all the connectiond for a room */

                auto isAborted = std::make_shared<bool>(false);

                res->onAborted([isAborted]() {
                    *isAborted = true;
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                });

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (apiKey != UserData::getInstance().adminApiKey) {
                        log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                        if (!*isAborted) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("401 Unauthorized");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                            });
                        }

                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, req, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                /** get rid from the request body */
                                std::vector<std::string> rids = parsedJson["rid"].get<std::vector<std::string>>();

                                /** Prepare the response JSON array */
                                nlohmann::json data = nlohmann::json::array();

                                /** Iterate over each `rid` and collect responses */
                                for (const auto& rid : rids) {
                                    nlohmann::json roomData;
                                    roomData["rid"] = rid;

                                    {
                                        tbb::concurrent_hash_map<std::string,
                                                                 tbb::concurrent_hash_map<std::string, bool>>::accessor
                                            outer_accessor;

                                        if (ThreadSafe::topics.find(outer_accessor, rid)) {
                                            nlohmann::json uidArray = nlohmann::json::array();

                                            for (const auto& entry : outer_accessor->second) {
                                                uidArray.push_back(entry.first);
                                            }

                                            roomData["uid"] = uidArray;
                                        } else {
                                            roomData["uid"] = nlohmann::json::array();
                                        }
                                    }

                                    data.push_back(roomData);
                                }

                                if (!*isAborted) {
                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res, data]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(data.dump());
                                    });
                                }
                            } catch (std::exception& e) {
                                if (!*isAborted) {
                                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res, e]() {
                                        res->writeStatus("400 Bad Request");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(R"({"message": "Invalid JSON format!"})");
                                    });
                                }
                            }
                        }
                    });
                } catch (std::exception& e) {
                    if (!*isAborted) {
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("500 Internal Server Error");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Internal server error!"})");
                        });
                    }
                }
            })
        .get(
            "/api/v1/users/subscribe/room/:rid",
            [this](auto* res, auto* req) {
                std::atomic<bool> isAborted = false;
                std::string rid = std::string(req->getParameter("rid"));
                std::string uid = std::string(req->getHeader("uid"));

                res->onAborted([&isAborted]() {
                    isAborted.store(true);
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                });

                try {
                    if (req->getHeader("api-key") != UserData::getInstance().clientApiKey) {
                        if (!isAborted.load()) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("401 Unauthorized");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                            });
                        }

                        return;
                    }

                    SLWebSocket* ws = nullptr;
                    worker_t* worker = nullptr;

                    {
                        /** the caller UID must have an active connection on this server */
                        tbb::concurrent_hash_map<std::string, WebSocketData>::const_accessor accessor;

                        if (!ThreadSafe::connections.find(accessor, uid)) {
                            if (!isAborted.load()) {
                                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                res->cork([res]() {
                                    res->writeStatus("404 Not Found");
                                    res->writeHeader("Content-Type", "application/json");
                                    res->end(R"({"message": "Invalid uid!"})");
                                });
                            }

                            return;
                        }

                        ws = accessor->second.ws;
                        worker = accessor->second.worker;
                    }

                    if (rid.empty() || rid.size() > 160) {
                        if (!isAborted.load()) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("400 Bad Request");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "The room ID length should be between 1 to 160 characters!"})");
                            });
                        }

                        return;
                    }

                    /** checking if the correct room type is received */
                    uint8_t roomType = parseRoomType(rid);
                    if (roomType == 255) {
                        if (!isAborted.load()) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("400 Bad Request");
                                res->writeHeader("Content-Type", "application/json");
                                res->end("{\"message\": \"The provided room type is invalid!\"}");
                            });
                        }

                        return;
                    }

                    {
                        /** reject if the user is already subscribed to this room */
                        tbb::concurrent_hash_map<std::string,
                                                 tbb::concurrent_hash_map<std::string, uint8_t>>::const_accessor
                            uid_to_rid_outer_accessor;

                        if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, uid)) {
                            auto& inner_map = uid_to_rid_outer_accessor->second;

                            tbb::concurrent_hash_map<std::string, uint8_t>::const_accessor inner_accessor;
                            if (inner_map.find(inner_accessor, rid)) {
                                if (!isAborted.load()) {
                                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("400 Bad Request");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(R"({"message": "You are already subscribed to the given room!"})");
                                    });
                                }

                                return;
                            }
                        }
                    }

                    /** checking if the user is banned from the given room */
                    {
                        tbb::concurrent_hash_map<
                            std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor outer_accessor;

                        if (ThreadSafe::bannedConnections.find(outer_accessor, rid) &&
                            outer_accessor->second.count(uid)) {

                            if (!isAborted.load()) {
                                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                res->cork([res]() {
                                    res->writeStatus("403 Forbidden");
                                    res->writeHeader("Content-Type", "application/json");
                                    res->end(R"({"message": "You have been banned from this room!"})");
                                });
                            }

                            return;
                        }
                    }

                    if (roomType == static_cast<uint8_t>(Rooms::PRIVATE) ||
                        roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE) ||
                        roomType == static_cast<uint8_t>(Rooms::PRIVATE_CACHE) ||
                        roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)) {
                        if (getWebhookStatus(Webhooks::ON_VERIFICATION_REQUEST) == 1) {
                            std::ostringstream payload;

                            payload << "{\"event\":\"ON_VERIFICATION_REQUEST\", " << "\"uid\":\"" << jsonEscape(uid)
                                    << "\", " << "\"rid\":\"" << jsonEscape(rid) << "\"}";

                            std::string body = payload.str();

                            /** Note: the X-HMAC-Signature header is computed and added inside
                     *  sendHTTPSPOSTRequestFireAndForget using the configured webhookSecret,
                     *  so no signature needs to be built here. */

                            int status =
                                sendHTTPSPOSTRequestFireAndForget(UserData::getInstance().webHookBaseUrl,
                                                                  UserData::getInstance().webhookPath, body, {}, true);

                            if (status != 200) {
                                if (!isAborted.load()) {
                                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("403 Forbidden");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end("{\"message\": \"You are not allowed to access this private room!\"}");
                                    });
                                }

                                return;
                            }
                        } else {
                            if (!isAborted.load()) {
                                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                res->cork([res]() {
                                    res->writeStatus("403 Forbidden");
                                    res->writeHeader("Content-Type", "application/json");
                                    res->end("{\"message\": \"The ON_VERIFICATION_REQUEST webhook must be enabled to "
                                             "activate private rooms!\"}");
                                });
                            }

                            return;
                        }
                    }

                    openConnection(ws, worker, rid, roomType);

                    if (!isAborted.load()) {
                        totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("200 OK");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Successfully subscribed to the given room!"})");
                        });
                    }
                } catch (std::exception& e) {
                    if (!isAborted.load()) {
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("500 Internal Server Error");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Internal server error!"})");
                        });
                    }
                }
            })
        .get("/api/v1/users/subscriptions/all",
             [this](auto* res, auto* req) {
                 /** get all the subscribed rooms from the given UIDs */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     std::string_view apiKey = req->getHeader("api-key");

                     if (apiKey != UserData::getInstance().adminApiKey) {
                         log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("401 Unauthorized");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     /** Prepare the response JSON array */
                     nlohmann::json data = nlohmann::json::array();

                     for (const auto& [uid, rids] : ThreadSafe::uidToRoomMapping) {
                         nlohmann::json roomData;
                         roomData["uid"] = uid;

                         std::vector<std::string> roomIDs;

                         for (const auto& [rid, _] : rids) {
                             roomIDs.push_back(rid);
                         }

                         roomData["rid"] = std::move(roomIDs);

                         data.push_back(std::move(roomData));
                     }

                     std::string response = data.dump();

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res, response]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(response);
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .post("/api/v1/users/subscriptions",
              [this](auto* res, auto* req) {
                  /** get all the subscribed rooms from the given UIDs */

                  auto isAborted = std::make_shared<bool>(false);

                  res->onAborted([isAborted]() {
                      *isAborted = true;
                      totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                  });

                  try {
                      std::string_view apiKey = req->getHeader("api-key");

                      if (apiKey != UserData::getInstance().adminApiKey) {
                          log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");
                          if (!*isAborted) {
                              totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                              res->cork([res]() {
                                  res->writeStatus("401 Unauthorized");
                                  res->writeHeader("Content-Type", "application/json");
                                  res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                              });
                          }

                          return;
                      }

                      std::string body;

                      body.reserve(1024);

                      res->onData(
                          [res, req, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
                              body.append(data.data(), data.length());

                              if (last) {
                                  try {
                                      nlohmann::json parsedJson = nlohmann::json::parse(body);

                                      /** get rid from the request body */
                                      std::vector<std::string> uids = parsedJson["uid"].get<std::vector<std::string>>();

                                      /** Prepare the response JSON array */
                                      nlohmann::json data = nlohmann::json::array();

                                      /** Iterate over each `rid` and collect responses */
                                      for (const auto& uid : uids) {
                                          nlohmann::json roomData;
                                          roomData["uid"] = uid;

                                          {
                                              tbb::concurrent_hash_map<
                                                  std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor
                                                  outer_accessor;

                                              if (ThreadSafe::uidToRoomMapping.find(outer_accessor, uid)) {
                                                  nlohmann::json ridArray = nlohmann::json::array();

                                                  for (const auto& entry : outer_accessor->second) {
                                                      ridArray.push_back(entry.first);
                                                  }

                                                  roomData["rid"] = ridArray;
                                              } else {
                                                  roomData["rid"] = nlohmann::json::array();
                                              }
                                          }

                                          data.push_back(roomData);
                                      }

                                      if (!*isAborted) {
                                          totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                          res->cork([res, data]() {
                                              res->writeStatus("200 OK");
                                              res->writeHeader("Content-Type", "application/json");
                                              res->end(data.dump());
                                          });
                                      }
                                  } catch (std::exception& e) {
                                      if (!*isAborted) {
                                          totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                          res->cork([res, e]() {
                                              res->writeStatus("400 Bad Request");
                                              res->writeHeader("Content-Type", "application/json");
                                              res->end(R"({"message": "Invalid JSON format!"})");
                                          });
                                      }
                                  }
                              }
                          });
                  } catch (std::exception& e) {
                      if (!*isAborted) {
                          totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                          res->cork([res]() {
                              res->writeStatus("500 Internal Server Error");
                              res->writeHeader("Content-Type", "application/json");
                              res->end(R"({"message": "Internal server error!"})");
                          });
                      }
                  }
              })
        .get("/api/v1/users/unsubscribe/room/:rid",
             [this](auto* res, auto* req) {
                 auto isAborted = std::make_shared<bool>(false);
                 std::string rid = std::string(req->getParameter("rid"));
                 std::string uid = std::string(req->getHeader("uid"));

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     if (req->getHeader("api-key") != UserData::getInstance().clientApiKey) {
                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("401 Unauthorized");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     SLWebSocket* ws = nullptr;
                     worker_t* worker = nullptr;

                     {
                         /** checking if there even is a connection with the provided UID */
                         tbb::concurrent_hash_map<std::string, WebSocketData>::const_accessor accessor;

                         if (!ThreadSafe::connections.find(accessor, uid)) {
                             if (!*isAborted) {
                                 totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                 res->cork([res]() {
                                     res->writeStatus("404 Not Found");
                                     res->writeHeader("Content-Type", "application/json");
                                     res->end(R"({"message": "Invalid uid!"})");
                                 });
                             }

                             return;
                         }

                         ws = accessor->second.ws;
                         worker = accessor->second.worker;
                     }

                     /** checking if the room length is valid */
                     if (rid.empty() || rid.length() > 160) {
                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("400 Bad Request");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(
                                     R"({"message": "The room id length should be between 1 to 160 characters!"})");
                             });
                         }

                         return;
                     }

                     /** checking if the correct room type is received */
                     uint8_t roomType = parseRoomType(rid);
                     if (roomType == 255) {
                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("400 Bad Request");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end("{\"message\": \"The provided room type is invalid!\"}");
                             });
                         }

                         return;
                     }

                     /** checking if the user is already unsubscribed to the given room */
                     {
                         tbb::concurrent_hash_map<std::string,
                                                  tbb::concurrent_hash_map<std::string, uint8_t>>::const_accessor
                             uid_to_rid_outer_accessor;

                         if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, uid)) {
                             const auto& inner_map = uid_to_rid_outer_accessor->second;

                             /** Check if the room is already present under the UID */
                             tbb::concurrent_hash_map<std::string, uint8_t>::const_accessor inner_accessor;
                             if (!inner_map.find(inner_accessor, rid)) {

                                 if (!*isAborted) {
                                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                     res->cork([res]() {
                                         res->writeStatus("400 Bad Request");
                                         res->writeHeader("Content-Type", "application/json");
                                         res->end(R"({"message": "You are not subscribed to the given room!"})");
                                     });
                                 }

                                 return;
                             }
                         } else {
                             if (!*isAborted) {
                                 totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                 res->cork([res]() {
                                     res->writeStatus("400 Bad Request");
                                     res->writeHeader("Content-Type", "application/json");
                                     res->end(R"({"message": "You are not subscribed to the given room!"})");
                                 });
                             }

                             return;
                         }
                     }

                     /** cloding the connection for the given rid */
                     closeConnection(ws, worker, rid, uid, roomType);

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Successfully unsubscribed from the given room!"})");
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .post(
            "/api/v1/broadcast",
            [this](auto* res, auto* req) {
                /** broadcast a message to everyone connected to the server */
                auto isAborted = std::make_shared<bool>(false);

                res->onAborted([isAborted]() {
                    *isAborted = true;
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                });

                try {
                    if (req->getHeader("api-key") != UserData::getInstance().adminApiKey) {
                        log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                        if (!*isAborted) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("401 Unauthorized");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                            });
                        }

                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, req, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                std::string message = parsedJson["message"].get<std::string>();
                                std::string messageToBroadcast = "{\"data\":\"" + jsonEscape(message) +
                                                                 "\",\"source\":\"admin\",\"rid\":\"" + BROADCAST +
                                                                 "\"}";

                                /** broadcast a message to all the rooms */
                                std::for_each(::workers.begin(), ::workers.end(), [messageToBroadcast](worker_t& w) {
                                    /** Defer the message publishing to the worker's loop */
                                    w.loop_->defer([&w, messageToBroadcast]() {
                                        w.app_->publish(BROADCAST, messageToBroadcast, uWS::OpCode::TEXT, true);
                                    });
                                });

                                if (!*isAborted) {
                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(
                                            R"({"message": "Successfully broadcasted the message to everyone on the server!"})");
                                    });
                                }
                            } catch (std::exception& e) {
                                if (!*isAborted) {
                                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res, e]() {
                                        res->writeStatus("400 Bad Request");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(R"({"message": "Invalid JSON format!"})");
                                    });
                                }
                            }
                        }
                    });
                } catch (std::exception& e) {
                    if (!*isAborted) {
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("500 Internal Server Error");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Internal server error!"})");
                        });
                    }
                }
            })
        .post(
            "/api/v1/rooms/broadcast",
            [this](auto* res, auto* req) {
                /** broadcast a message to a particular room */

                auto isAborted = std::make_shared<bool>(false);

                res->onAborted([isAborted]() {
                    *isAborted = true;
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                });

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (apiKey != UserData::getInstance().adminApiKey) {
                        log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                        if (!*isAborted) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("403");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                            });
                        }

                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, req, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                std::string message = parsedJson["message"].get<std::string>();
                                std::vector<std::string> rids = parsedJson["rid"].get<std::vector<std::string>>();

                                for (const auto& rid : rids) {
                                    std::string messageToBroadcast = "{\"data\":\"" + jsonEscape(message) +
                                                                     "\",\"source\":\"admin\",\"rid\":\"" +
                                                                     jsonEscape(rid) + "\"}";

                                    /** broadcast a message to a specific room */
                                    std::for_each(
                                        ::workers.begin(), ::workers.end(), [messageToBroadcast, rid](worker_t& w) {
                                            /** Defer the message publishing to the worker's loop */
                                            w.loop_->defer([&w, messageToBroadcast, rid]() {
                                                w.app_->publish(rid, messageToBroadcast, uWS::OpCode::TEXT, true);
                                            });
                                        });
                                }

                                if (!*isAborted) {
                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(
                                            R"({"message": "Successfully broadcasted the message to the given rooms!"})");
                                    });
                                }
                            } catch (std::exception& e) {
                                if (!*isAborted) {
                                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("400 Bad Request");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(R"({"message": "Invalid JSON format!"})");
                                    });
                                }
                            }
                        }
                    });
                } catch (std::exception& e) {
                    if (!*isAborted) {
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("500 Internal Server Error");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Internal server error!"})");
                        });
                    }
                }
            })
        .post(
            "/api/v1/users/broadcast",
            [this](auto* res, auto* req) {
                /** broadcast a message to a particular connection */

                auto isAborted = std::make_shared<bool>(false);

                res->onAborted([isAborted]() {
                    *isAborted = true;
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                });

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (apiKey != UserData::getInstance().adminApiKey) {
                        log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                        if (!*isAborted) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("403");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                            });
                        }

                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, req, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                std::string message = parsedJson["message"].get<std::string>();
                                std::vector<std::string> uids = parsedJson["uid"].get<std::vector<std::string>>();

                                for (const auto& uid : uids) {
                                    std::string messageToBroadcast = "{\"data\":\"" + jsonEscape(message) +
                                                                     "\",\"source\":\"admin\",\"rid\":\"" +
                                                                     jsonEscape(uid) + "\"}";

                                    /** broadcast a message to a specific member of a room */
                                    std::for_each(
                                        ::workers.begin(), ::workers.end(), [messageToBroadcast, uid](worker_t& w) {
                                            /** Defer the message publishing to the worker's loop */
                                            w.loop_->defer([&w, messageToBroadcast, uid]() {
                                                w.app_->publish(uid, messageToBroadcast, uWS::OpCode::TEXT, true);
                                            });
                                        });
                                }

                                if (!*isAborted) {
                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(
                                            R"({"message": "Successfully broadcasted the message to the given connections!"})");
                                    });
                                }
                            } catch (std::exception& e) {
                                if (!*isAborted) {
                                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("400 Bad Request");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(R"({"message": "Invalid JSON format!"})");
                                    });
                                }
                            }
                        }
                    });
                } catch (std::exception& e) {
                    if (!*isAborted) {
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("500 Internal Server Error");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Internal server error!"})");
                        });
                    }
                }
            })
        .post(
            "/api/v1/rooms/users/ban",
            [this](auto* res, auto* req) {
                /** ban all the users in a room and prevent them from connecting again (it will disconnect the user from the server) */

                auto isAborted = std::make_shared<bool>(false);

                res->onAborted([isAborted]() {
                    *isAborted = true;
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                });

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (apiKey != UserData::getInstance().adminApiKey) {
                        log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                        if (!*isAborted) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("403");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                            });
                        }

                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, req, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                /** saving all the banned connections in a map */
                                for (const auto& item : parsedJson) {
                                    /** Extract `rid` and `uid` from each item in the request */
                                    std::string rid = item["rid"];
                                    std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                                    /** checking if the correct room type is received
                             *  ("global" is a valid ban target that has no room prefix) */
                                    uint8_t roomType = parseRoomType(rid);
                                    if (roomType == 255 && rid != "global") {
                                        if (!*isAborted) {
                                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                            res->cork([res]() {
                                                res->writeStatus("400 Bad Request");
                                                res->writeHeader("Content-Type", "application/json");
                                                res->end("{\"message\": \"The provided room type is invalid!\"}");
                                            });
                                        }

                                        return;
                                    }

                                    /** banning the user */
                                    {
                                        tbb::concurrent_hash_map<std::string,
                                                                 tbb::concurrent_hash_map<std::string, bool>>::accessor
                                            global_accessor;
                                        tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                                        /** Try to find or insert the outer map entry */
                                        if (!ThreadSafe::bannedConnections.find(global_accessor, rid)) {
                                            ThreadSafe::bannedConnections.insert(global_accessor, rid);
                                        }

                                        for (const auto& uid : uids) {
                                            /** Check if uid already exists before inserting */
                                            if (!global_accessor->second.find(user_accessor, uid)) {
                                                global_accessor->second.insert(user_accessor, uid);
                                                user_accessor->second = true;

                                                /** Fetch the connection for the given uid from the connections map */
                                                tbb::concurrent_hash_map<std::string, WebSocketData>::accessor
                                                    conn_accessor;
                                                if (ThreadSafe::connections.find(conn_accessor, uid)) {
                                                    SLWebSocket* ws = conn_accessor->second.ws;
                                                    worker_t* worker = conn_accessor->second.worker;

                                                    /** Disconnect the WebSocket or perform any other disconnection logic */
                                                    if (rid == "global") {
                                                        worker->loop_->defer([ws]() {
                                                            ws->end(1008, "{\"data\":\"YOU_HAVE_BEEN_BANNED\", "
                                                                          "\"source\":\"admin\"}");
                                                        });
                                                    } else {
                                                        /** cloding the connection for the given rid */
                                                        closeConnection(ws, worker, rid, uid, roomType);

                                                        /** Tell the user in case of room ban */
                                                        ws->send("{\"data\":\"YOU_HAVE_BEEN_BANNED\", "
                                                                 "\"source\":\"admin\", \"rid\":\"" +
                                                                     jsonEscape(rid) + "\"}",
                                                                 uWS::OpCode::TEXT, true);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                log(LogLevel::INFO, "Admin API: users banned via /api/v1/rooms/users/ban");

                                if (!*isAborted) {
                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(
                                            R"({"message": "Given users are successfully banned from the given rooms!"})");
                                    });
                                }
                            } catch (std::exception& e) {
                                if (!*isAborted) {
                                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("400 Bad Request");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(R"({"message": "Invalid JSON format!"})");
                                    });
                                }
                            }
                        }
                    });
                } catch (std::exception& e) {
                    if (!*isAborted) {
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("500 Internal Server Error");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Internal server error!"})");
                        });
                    }
                }
            })
        .post(
            "/api/v1/rooms/users/unban",
            [this](auto* res, auto* req) {
                /** ban all the users in a room and prevent them from connecting again (it will disconnect the user from the server) */

                auto isAborted = std::make_shared<bool>(false);

                res->onAborted([isAborted]() {
                    *isAborted = true;
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                });

                try {
                    std::string_view apiKey = req->getHeader("api-key");

                    if (apiKey != UserData::getInstance().adminApiKey) {
                        log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                        if (!*isAborted) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("403");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                            });
                        }

                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, req, body = std::move(body), isAborted](std::string_view data,
                                                                              bool last) mutable {
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                for (const auto& item : parsedJson) {
                                    /** Extract `rid` and `uid` from each item in the request */
                                    std::string rid = item["rid"];
                                    std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                                    {
                                        tbb::concurrent_hash_map<std::string,
                                                                 tbb::concurrent_hash_map<std::string, bool>>::accessor
                                            global_accessor;
                                        tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                                        /** Check if the room exists before trying to erase */
                                        if (ThreadSafe::bannedConnections.find(global_accessor, rid)) {
                                            for (const auto& uid : uids) {
                                                /** Check if the user exists before erasing */
                                                if (global_accessor->second.find(user_accessor, uid)) {
                                                    global_accessor->second.erase(user_accessor);
                                                }
                                            }

                                            /** If the inner map becomes empty, erase the entire entry */
                                            if (global_accessor->second.empty()) {
                                                ThreadSafe::bannedConnections.erase(global_accessor);
                                            }
                                        }
                                    }
                                }

                                if (!*isAborted) {
                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(
                                            R"({"message": "Given users are successfully unbanned from the given rooms!"})");
                                        log(LogLevel::INFO, "Admin API: users unbanned via /api/v1/rooms/users/unban");
                                    });
                                }
                            } catch (std::exception& e) {
                                if (!*isAborted) {
                                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("400 Bad Request");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(R"({"message": "Invalid JSON format!"})");
                                    });
                                }
                            }
                        }
                    });
                } catch (std::exception& e) {
                    if (!*isAborted) {
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("500 Internal Server Error");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Internal server error!"})");
                        });
                    }
                }
            })
        .put("/api/v1/server/messaging/:action",
             [this](auto* res, auto* req) {
                 /** enable or disable message sending at the server level (for everyone) */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     std::string_view apiKey = req->getHeader("api-key");
                     std::string_view action = req->getParameter("action");

                     if (apiKey != UserData::getInstance().adminApiKey) {
                         log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("403");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     if (action == "enable") {
                         isMessagingDisabled.store(false, std::memory_order_relaxed);
                     } else if (action == "disable") {
                         isMessagingDisabled.store(true, std::memory_order_relaxed);
                     } else {
                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("400 Bad Request");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Invalid action!"})");
                             });
                         }
                         return;
                     }

                     log(LogLevel::INFO, "Admin API: server-wide messaging ", action, "d");

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res, action]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");

                             if (action == "enable")
                                 res->end(R"({"message": "Messaging successfully enabled for everyone!"})");
                             else
                                 res->end(R"({"message": "Messaging successfully disabled for everyone!"})");
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .post(
            "/api/v1/rooms/messaging/:action",
            [this](auto* res, auto* req) {
                /** enable or disable messaging at room level */

                auto isAborted = std::make_shared<bool>(false);

                res->onAborted([isAborted]() {
                    *isAborted = true;
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                });

                try {
                    std::string_view apiKey = req->getHeader("api-key");
                    std::string_view action = req->getParameter("action");

                    if (apiKey != UserData::getInstance().adminApiKey) {
                        log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");

                        if (!*isAborted) {
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("403");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                            });
                        }

                        return;
                    }

                    std::string body;

                    body.reserve(1024);

                    res->onData([res, req, body = std::move(body), action, isAborted](std::string_view data,
                                                                                      bool last) mutable {
                        body.append(data.data(), data.length());

                        if (last) {
                            try {
                                nlohmann::json parsedJson = nlohmann::json::parse(body);

                                for (const auto& item : parsedJson) {
                                    /** Extract `rid` and `uid` from each item in the request */
                                    std::string rid = item["rid"];
                                    std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                                    if (action == "enable") {
                                        {
                                            tbb::concurrent_hash_map<
                                                std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor
                                                global_accessor;
                                            tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                                            /** Check if the room exists before trying to erase */
                                            if (ThreadSafe::disabledConnections.find(global_accessor, rid)) {
                                                for (const auto& uid : uids) {
                                                    /** Check if the user exists before erasing */
                                                    if (global_accessor->second.find(user_accessor, uid)) {
                                                        global_accessor->second.erase(user_accessor);
                                                    }
                                                }

                                                /** If the inner map becomes empty, erase the entire entry */
                                                if (global_accessor->second.empty()) {
                                                    ThreadSafe::disabledConnections.erase(global_accessor);
                                                }
                                            }
                                        }
                                    } else if (action == "disable") {
                                        {
                                            tbb::concurrent_hash_map<
                                                std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor
                                                global_accessor;
                                            tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                                            /** Try to find or insert the outer map entry */
                                            if (!ThreadSafe::disabledConnections.find(global_accessor, rid)) {
                                                ThreadSafe::disabledConnections.insert(global_accessor, rid);
                                            }

                                            for (const auto& uid : uids) {
                                                /** Check if uid already exists before inserting */
                                                if (!global_accessor->second.find(user_accessor, uid)) {
                                                    global_accessor->second.insert(user_accessor, uid);
                                                    user_accessor->second = true;
                                                }
                                            }
                                        }
                                    } else {
                                        if (!*isAborted) {
                                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                            res->cork([res]() {
                                                res->writeStatus("400 Bad Request");
                                                res->writeHeader("Content-Type", "application/json");
                                                res->end(R"({"message": "Invalid action!"})");
                                            });
                                        }

                                        return;
                                    }
                                }

                                log(LogLevel::INFO, "Admin API: per-room messaging ", action, "d for given users");

                                if (!*isAborted) {
                                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res, action]() {
                                        res->writeStatus("200 OK");
                                        res->writeHeader("Content-Type", "application/json");

                                        if (action == "enable")
                                            res->end(
                                                R"({"message": "Messaging successfully enabled for the given members in the given rooms!"})");
                                        else
                                            res->end(
                                                R"({"message": "Messaging successfully disabled for the given members in the given rooms!"})");
                                    });
                                }
                            } catch (std::exception& e) {
                                if (!*isAborted) {
                                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                    res->cork([res]() {
                                        res->writeStatus("400 Bad Request");
                                        res->writeHeader("Content-Type", "application/json");
                                        res->end(R"({"message": "Invalid JSON format!"})");
                                    });
                                }
                            }
                        }
                    });
                } catch (std::exception& e) {
                    if (!*isAborted) {
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("500 Internal Server Error");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Internal server error!"})");
                        });
                    }
                }
            })
        .get("/api/v1/users/banned",
             [this](auto* res, auto* req) {
                 /** Handle the request to fetch all banned connections */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     std::string_view apiKey = req->getHeader("api-key");

                     if (apiKey != UserData::getInstance().adminApiKey) {
                         log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");
                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("403");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     nlohmann::json data = nlohmann::json::array();

                     for (const auto& [rid, users] : ThreadSafe::bannedConnections) {
                         nlohmann::json roomData;
                         roomData["rid"] = rid;

                         std::vector<std::string> userKeys;

                         for (const auto& [uid, _] : users) {
                             userKeys.push_back(uid);
                         }

                         roomData["uid"] = std::move(userKeys);

                         data.push_back(std::move(roomData));
                     }

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res, data]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(data.dump());
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .get("/api/v1/users/messaging/disabled",
             [this](auto* res, auto* req) {
                 /** Handle the request to fetch all disabled connections */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     std::string_view apiKey = req->getHeader("api-key");

                     if (apiKey != UserData::getInstance().adminApiKey) {
                         log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");
                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("403");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     nlohmann::json json_response = nlohmann::json::array();

                     for (const auto& [rid, users] : ThreadSafe::disabledConnections) {
                         nlohmann::json roomData;
                         roomData["rid"] = rid;

                         std::vector<std::string> userKeys;

                         for (const auto& [uid, _] : users) {
                             userKeys.push_back(uid);
                         }

                         roomData["uid"] = std::move(userKeys);

                         json_response.push_back(std::move(roomData));
                     }

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res, json_response]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(json_response.dump());
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .get("/api/v1/messages/room/:rid",
             [this](auto* res, auto* req) {
                 /** retrieve the messages for cache rooms (for other rooms no data will be returned) */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     std::string_view rid = req->getParameter("rid");
                     std::string_view apiKey = req->getHeader("api-key");
                     std::string_view uid = req->getHeader("uid");

                     {
                         tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor
                             outer_accessor;

                         if (!ThreadSafe::topics.find(outer_accessor, std::string(rid))) {
                             if (!*isAborted) {
                                 totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                 res->cork([res]() {
                                     res->writeStatus("403 Forbidden");
                                     res->writeHeader("Content-Type", "application/json");
                                     res->end(R"({"message": "Access denied!"})");
                                 });
                             }

                             return;
                         } else {
                             /** Access the inner map corresponding to 'rid' */
                             tbb::concurrent_hash_map<std::string, bool>& inner_map = outer_accessor->second;

                             /** Create an accessor for the inner map */
                             tbb::concurrent_hash_map<std::string, bool>::accessor inner_accessor;

                             /** Check if value exists in the inner map (uid) */
                             if (!inner_map.find(inner_accessor, std::string(uid))) {
                                 if (!*isAborted) {
                                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                     res->cork([res]() {
                                         res->writeStatus("403 Forbidden");
                                         res->writeHeader("Content-Type", "application/json");
                                         res->end(R"({"message": "Access denied!"})");
                                     });
                                 }

                                 return;
                             }
                         }
                     }

                     write_worker(std::string(rid), "", true);

                     if (apiKey != UserData::getInstance().clientApiKey) {

                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("403 Forbidden");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res, rid]() {
                             res->writeStatus("200 OK");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(read_worker(std::string(rid)));
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .del("/api/v1/database",
             [this](auto* res, auto* req) {
                 /** delete all the data present in the LMDB database */

                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     std::string_view apiKey = req->getHeader("api-key");

                     if (apiKey != UserData::getInstance().adminApiKey) {
                         log(LogLevel::WARN, "Admin API: request rejected (invalid admin api key)");
                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("403 Forbidden");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                             });
                         }

                         return;
                     }

                     MDB_txn* txn = nullptr;

                     try {
                         if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
                             throw std::runtime_error("Failed to begin transaction.");
                         }

                         /** drop all keys but keep the database structure (0 = truncate) */
                         if (mdb_drop(txn, g_dbi, 0) != 0) {
                             mdb_txn_abort(txn);
                             throw std::runtime_error("Failed to drop database.");
                         }

                         if (mdb_txn_commit(txn) != 0) {
                             throw std::runtime_error("Failed to commit transaction.");
                         }

                         log(LogLevel::WARN, "Admin API: LMDB message store TRUNCATED via DELETE /api/v1/database");

                         if (!*isAborted) {
                             totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res]() {
                                 res->writeStatus("200 OK");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Database truncated successfully!"})");
                             });
                         }
                     } catch (const std::exception& e) {
                         /** abort the transaction so it doesn't leak on the error path */
                         if (txn)
                             mdb_txn_abort(txn);

                         if (!*isAborted) {
                             totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                             res->cork([res, e]() {
                                 res->writeStatus("500 Internal Server Error");
                                 res->writeHeader("Content-Type", "application/json");
                                 res->end(R"({"message": "Internal server error!"})");
                             });
                         }
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .get("/api/v1/ping",
             [](auto* res, auto* /*req*/) {
                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     if (!*isAborted) {
                         totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("200 OK");
                             res->end("pong!");
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .any("/*",
             [](auto* res, auto* /*req*/) {
                 auto isAborted = std::make_shared<bool>(false);

                 res->onAborted([isAborted]() {
                     *isAborted = true;
                     totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
                 });

                 try {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("404 Not Found");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "The requested resource is not found!"})");
                         });
                     }
                 } catch (std::exception& e) {
                     if (!*isAborted) {
                         totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                         res->cork([res]() {
                             res->writeStatus("500 Internal Server Error");
                             res->writeHeader("Content-Type", "application/json");
                             res->end(R"({"message": "Internal server error!"})");
                         });
                     }
                 }
             })
        .listen(listenPort, [this, listenPort](auto* token) {
            listen_socket_ = token;
            if (listen_socket_) {
                log(LogLevel::INFO, "Thread ", std::this_thread::get_id(), " listening on port ", listenPort);
            } else {
                log(LogLevel::ERROR, "Thread ", std::this_thread::get_id(), " failed to listen on port ", listenPort);
            }
        });

    app_->run();

    io_context.stop();

    log(LogLevel::INFO, "Thread ", std::this_thread::get_id(), " exiting");
}


int main() {
    /** SL_LOG_LEVEL=debug|info|warn|error (default info) */
    if (const char* lv = std::getenv("SL_LOG_LEVEL")) {
        std::string v(lv);
        if (v == "debug")
            g_logLevel = static_cast<int>(LogLevel::DEBUG);
        else if (v == "info")
            g_logLevel = static_cast<int>(LogLevel::INFO);
        else if (v == "warn")
            g_logLevel = static_cast<int>(LogLevel::WARN);
        else if (v == "error")
            g_logLevel = static_cast<int>(LogLevel::ERROR);
    }

    log(LogLevel::INFO, "Main thread Id : ", std::this_thread::get_id());

    /** Raise the fd soft limit to the hard limit: every connection costs an fd, and
     *  the common 10240 soft default caps the server at ~10k connections — worse,
     *  accept() then fails with EMFILE in a hot loop and the server appears hung. */
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
            rl.rlim_cur = rl.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rl);
            getrlimit(RLIMIT_NOFILE, &rl);
        }
        log(LogLevel::INFO, "File descriptor limit : ", (unsigned long long)rl.rlim_cur);
    }

    /** Config is compiled in (UserData defaults); just init the feature-status map. */
    populateFeatureStatus(UserData::getInstance().features);

    if (UserData::getInstance().clientApiKey == "change-me-client-key" ||
        UserData::getInstance().adminApiKey == "change-me-admin-key") {
        log(LogLevel::WARN, "SECURITY WARNING: default API key(s) in use. "
                            "Set real keys in UserData (clientApiKey / adminApiKey) and rebuild, "
                            "or override them via /api/v1/invalidate before exposing this server.");
    }

    init_env();
    log(LogLevel::INFO,
        "Standalone mode (plaintext HTTP/WS; TLS terminated upstream), in-memory config, port=", SL_LISTEN_PORT);

    int numThreads = std::thread::hardware_concurrency();
    /** Optional override: cap worker threads independent of core count (e.g. when
     *  the process is pinned to fewer cores than the host reports). */
    if (const char* t = std::getenv("SL_THREADS")) {
        int n = std::atoi(t);
        if (n > 0)
            numThreads = n;
    }
    if (numThreads < 1)
        numThreads = 1;

    log(LogLevel::INFO, "Number of threads available : ", numThreads);

    workers.resize(numThreads);

    for (auto& w : workers) {
        w.thread_ = std::make_shared<std::thread>([&w]() { w.work(); });
    }

    std::for_each(workers.begin(), workers.end(), [](worker_t& w) { w.thread_->join(); });

    log(LogLevel::INFO, "All workers exited; shutting down.");

    mdb_env_close(env);

    return 0;
}