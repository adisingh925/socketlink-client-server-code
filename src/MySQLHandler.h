#pragma once

#include <mysql/mysql.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "Config.h"
#include "Logging.h"

/** Total MySQL batch writes (exposed in /api/v1/metrics). */

inline std::atomic<unsigned long long> totalMysqlDBWrites{0};

class MySQLConnectionHandler {
private:
    MYSQL* conn;
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> batch_data;

    /** Rate-limits write-path reconnect attempts: connecting blocks the calling
     *  (event-loop) thread for up to the 3s connect timeout, so a dead DB must
     *  not trigger that on every batch. */
    std::chrono::steady_clock::time_point lastReconnectAttempt_{};

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
                return; /** every call below would dereference a null handle */
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
                /** connection died since startup: try to re-establish it, at most
                 *  once per 30s, so buffered rows drain again instead of being
                 *  silently dropped at the 3x-batch cap */
                auto now = std::chrono::steady_clock::now();
                if (now - lastReconnectAttempt_ < std::chrono::seconds(30)) {
                    return false;
                }
                lastReconnectAttempt_ = now;
                createConnection();
                if (!conn) {
                    return false;
                }
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
                /** copy the error text BEFORE closing: mysql_stmt_error(stmt) after
                 *  mysql_stmt_close(stmt) reads freed memory */
                std::string stmtError = mysql_stmt_error(stmt);
                mysql_stmt_close(stmt);
                log(LogLevel::ERROR, "Batch Insertion Error : " + stmtError);
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

/**
 * Dedicated MySQL writer thread (same pattern as the webhook dispatcher).
 *
 * Previously every worker owned a MySQLConnectionHandler and executed the batched
 * multi-row INSERT synchronously ON ITS EVENT LOOP — load tests measured a ~4x
 * delivery collapse with SQL integration enabled, because each 1000-row insert
 * froze that worker's entire reactor. Event-loop threads now only enqueue the row
 * here (a few string moves under a mutex); this thread owns the single MySQL
 * connection and does all blocking work.
 *
 * Rows sit in a bounded queue: if MySQL cannot keep up, the OLDEST rows are
 * dropped and counted (dropped_db_rows in /metrics) — memory stays bounded and
 * the event loops never stall, matching the webhook/logging queue policy.
 * Control operations (flush / reconnect / disconnect) travel through a separate
 * unbounded command queue so overload can never discard them, and every MySQL
 * call still happens on this one thread.
 */
class MySQLWriter {
public:
    static MySQLWriter& getInstance() {
        static MySQLWriter instance;
        return instance;
    }

    /** Queue one message row for insertion. Non-blocking; event-loop safe. */
    void enqueue(std::string insertTime, std::string message, std::string uid, std::string rid) {
        bool droppedOne = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (rows_.size() >= maxQueuedRows_) {
                rows_.pop_front();
                droppedRows_.fetch_add(1, std::memory_order_relaxed);
                droppedOne = true;
            }
            rows_.push_back(Row{std::move(insertTime), std::move(message), std::move(uid), std::move(rid)});
        }
        cv_.notify_one();

        if (droppedOne) {
            unsigned long long d = droppedRows_.load(std::memory_order_relaxed);
            if (d == 1 || d % 100000 == 0) {
                log(LogLevel::WARN, "MySQL writer queue full: dropping oldest rows (total dropped: ", d, ")");
            }
        }
    }

    /** Flush the connection handler's pending batch (e.g. /api/v1/mysql/sync, shutdown). */
    void requestFlush() { enqueueCommand(Command::FLUSH); }

    /** (Re)connect with the current config (invalidate changed the DB settings). */
    void requestReconnect() { enqueueCommand(Command::RECONNECT); }

    /** Flush then drop the connection (SQL integration disabled). */
    void requestDisconnect() { enqueueCommand(Command::DISCONNECT); }

    unsigned long long droppedCount() const { return droppedRows_.load(std::memory_order_relaxed); }

    MySQLWriter(const MySQLWriter&) = delete;
    MySQLWriter& operator=(const MySQLWriter&) = delete;

private:
    struct Row {
        std::string insertTime;
        std::string message;
        std::string uid;
        std::string rid;
    };

    enum class Command : uint8_t { FLUSH, RECONNECT, DISCONNECT };

    MySQLWriter() : writer_([this]() { run(); }) {}

    ~MySQLWriter() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
        cv_.notify_all();
        if (writer_.joinable()) {
            writer_.join();
        }
    }

    void enqueueCommand(Command c) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            commands_.push_back(c);
        }
        cv_.notify_one();
    }

    void run() {
        /** the handler (and thus the MySQL connection) is created and used
         *  exclusively on this thread */
        auto handler = std::make_unique<MySQLConnectionHandler>();

        while (true) {
            Row row;
            Command cmd{};
            bool haveRow = false, haveCmd = false;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this]() { return !rows_.empty() || !commands_.empty() || !running_; });
                if (!running_ && rows_.empty() && commands_.empty()) {
                    break;
                }
                if (!commands_.empty()) { /** commands take priority and are never dropped */
                    cmd = commands_.front();
                    commands_.pop_front();
                    haveCmd = true;
                } else if (!rows_.empty()) {
                    row = std::move(rows_.front());
                    rows_.pop_front();
                    haveRow = true;
                }
            }

            if (haveCmd) {
                switch (cmd) {
                    case Command::FLUSH:
                        handler->flushRemainingData();
                        break;
                    case Command::RECONNECT:
                        handler->manualCreateConnection();
                        break;
                    case Command::DISCONNECT:
                        handler->flushRemainingData();
                        handler->disconnect();
                        break;
                }
            } else if (haveRow) {
                handler->insertSingleData(row.insertTime, row.message, row.uid, row.rid);
            }
        }

        handler->flushRemainingData(); /** drain on clean exit */
    }

    std::deque<Row> rows_;
    std::deque<Command> commands_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool running_ = true;
    std::atomic<unsigned long long> droppedRows_{0};
    /** ~50k rows; at the 10KB message cap that bounds worst-case queue memory
     *  to ~500MB, and at typical sizes far less. DB slower than ingress -> the
     *  oldest rows drop (counted) instead of stalling loops or growing memory. */
    static constexpr size_t maxQueuedRows_ = 50000;
    std::thread writer_;
};
