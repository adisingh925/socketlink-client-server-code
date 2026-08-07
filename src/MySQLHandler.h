#pragma once

#include <mysql/mysql.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>
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
