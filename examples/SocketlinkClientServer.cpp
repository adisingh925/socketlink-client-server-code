/* We simply call the root header file "App.h", giving you uWS::App and uWS::SSLApp */
#include "App.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
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
#include "simdjson.h"

/** is logs enabled */
constexpr bool LOGS_ENABLED = true;

std::atomic<unsigned long long> totalMysqlDBWrites{0}; /** Total writes to the MySQL database */

/** log the sata in the console */
void log(const std::string& message) {
    if (LOGS_ENABLED) {
        std::cout << message << std::endl;
    }
}

/******************************************************************************************************************************************************************************/

class UserData {
private:
    /** Private constructor to prevent instantiation */ 
    UserData() = default;

public:
    /** server configuration variables, can be changed on user demand */
    unsigned int msgSizeAllowedInBytes = 10240;
    unsigned int maxBackpressureInBytes = 4096;
    unsigned short idleTimeoutInSeconds = 60;
    unsigned short maxLifetimeInMinutes = 0;

    unsigned long long maxMonthlyPayloadInBytes;
    int connections;
    std::string clientApiKey;
    std::string adminApiKey;

    /** webhook configuration */
    std::string webHookBaseUrl;
    std::string webhookPath;
    std::string webhookSecret;
    uint64_t webhooks;
    std::string webhookIP;

    /** mysql db configuration */
    int mysqlDBCommitBatchSize = 1000;
    std::string dbHost;
    int dbPort;
    std::string dbUser;
    std::string dbPassword;
    std::string dbName;

    /** lmdb configurations */
    int lmdbCommitBatchSize = 1000;
    unsigned long long lmdbDatabaseSizeInBytes;

    /** auto populated according to the values of above variables */
    uint32_t features;

    /** user info */
    std::string subdomain;
    std::string ip;

    /** Public static method to get the single instance */ 
    static UserData& getInstance() {
        static UserData instance;
        return instance;
    }

    /** Delete copy constructor and assignment operator */ 
    UserData(const UserData&) = delete;
    UserData& operator=(const UserData&) = delete;
};

class MySQLConnectionHandler {
private:
    MYSQL *conn;  /**< MySQL connection object */
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> batch_data;  /**< Holds batch data to be inserted */

    /** Custom exception class for MySQL errors */ 
    class MySQLException : public std::runtime_error {
    public:
        explicit MySQLException(const std::string& message)
            : std::runtime_error(message) {}
    };

    /**
     * Establishes a connection to the MySQL database.
     * Closes any existing connection and initializes a new one.
     */
    void createConnection() {
        try {
            if (conn) {
                mysql_close(conn);  /**< Close existing connection */
                conn = nullptr;
            }

            conn = mysql_init(NULL);  /**< Initialize a new MySQL connection */
            if (!conn) {
                log("MySQL Initialization Error");
            }

            /** Set timeout for MySQL connection (in seconds) */
            unsigned int timeout = 3;
            mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

            /** Attempt to establish a connection using credentials */
            if (!mysql_real_connect(
                conn,
                UserData::getInstance().dbHost.c_str(),
                UserData::getInstance().dbUser.c_str(),
                UserData::getInstance().dbPassword.c_str(),
                UserData::getInstance().dbName.c_str(),
                UserData::getInstance().dbPort, NULL, 0
            )) {
                log("MySQL Connection Error : " + std::string(mysql_error(conn)));
                mysql_close(conn);  /**< Close the connection on error */
                conn = nullptr;
            } else {
                mysql_query(conn, "SET SESSION query_cache_type = OFF");  /**< Disable query caching */
                createTableIfNotExists();  /**< Create the table if it doesn't exist */
            }
        } catch (const MySQLException& e) {
            std::cerr << "MySQL Error : " << e.what() << std::endl;
        }
    }

    /**
     * Ensures there is an active MySQL connection.
     * If not, it creates a new connection.
     */
    void checkConnection() {
        try {
            if (!conn) {
                createConnection();  /**< Create a new connection if not present */
            }
        } catch (const MySQLException& e) {
            std::cerr << "Connection Error : " << e.what() << std::endl;
        }
    }

    /**
     * Creates the `socketlink_messages` table if it doesn't already exist.
     * This table will store messages and metadata like timestamps, identifier, and room name.
     */
    void createTableIfNotExists() {
        try {
            if (!conn) return;

            const char* query =
                "CREATE TABLE IF NOT EXISTS socketlink_messages ("
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
            std::cerr << "Table Creation Error : " << e.what() << std::endl;
        }
    }

    /**
     * Inserts the batch data into the `socketlink_messages` table.
     * The method prepares a batch query and uses parameterized statements to avoid SQL injection.
     * 
     * @return true if the batch insertion is successful, false otherwise.
     */
    bool insertBatchData() {
        try {
            if (!conn){
                return false;
            }

            /** Build the query for batch insertion */
            std::string query = "INSERT INTO socketlink_messages (insert_time, message, uid, rid) VALUES ";
            for (size_t i = 0; i < batch_data.size(); ++i) {
                if (i > 0) query += ", ";
                query += "(?, ?, ?, ?)";
            }

            MYSQL_STMT* stmt = mysql_stmt_init(conn);  /**< Initialize the prepared statement */
            if (!stmt || mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
                mysql_stmt_close(stmt);  /**< Close the statement on exception */
                log("Batch Insertion Error : " + std::string(mysql_stmt_error(stmt)));
                return false;
            }

            /** Bind parameters to the prepared statement */
            MYSQL_BIND bind[4 * batch_data.size()];
            memset(bind, 0, sizeof(bind));
            int paramIndex = 0;

            /** Loop through batch data and bind values */
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

            /** Bind the parameters to the statement and execute */
            if (mysql_stmt_bind_param(stmt, bind) || mysql_stmt_execute(stmt)) {
                mysql_stmt_close(stmt);  /**< Close the statement on exception */
                log("Batch Insertion Error : " + std::string(mysql_stmt_error(stmt)));
                return false;
            }

            mysql_stmt_close(stmt);  /**< Close the statement after execution */
            batch_data.clear();  /**< Clear the batch data after successful insertion */
            totalMysqlDBWrites.fetch_add(1, std::memory_order_relaxed);  /**< Increment the total write count */
            return true;
        } catch (const MySQLException& e) {
            std::cerr << "Batch Insertion Error : " << e.what() << std::endl;

            return false;
        }
    }

public:
    /**
     * Constructor initializes the MySQL connection.
     */
    MySQLConnectionHandler() : conn(nullptr) {
        try {
            createConnection();  /**< Create the initial connection */
        } catch (const MySQLException& e) {
            std::cerr << "Constructor Error : " << e.what() << std::endl;
        }
    }

    /**
     * Destructor ensures that the MySQL connection is closed when the object is destroyed.
     */
    ~MySQLConnectionHandler() {
        try {
            if (conn) {
                mysql_close(conn);  /**< Close the connection if it exists */
            }
        } catch (const MySQLException& e) {
            std::cerr << "Destructor Error : " << e.what() << std::endl;
        }
    }

    /**
     * Inserts a single message into the batch data.
     * If the batch size reaches the threshold (1000), it triggers the batch insert.
     * 
     * @param insert_time The timestamp of the message.
     * @param message The message content.
     * @param identifier A unique identifier for the message.
     * @param room The room name where the message belongs.
     */
    void insertSingleData(const std::string& insert_time, const std::string& message, const std::string& identifier, const std::string& room) {
        try {
            /** It will be retried 3 times, after that the batch will be dropped to protect excessive memory use */
            if(batch_data.size() <= (UserData::getInstance().mysqlDBCommitBatchSize * 3)){
                batch_data.emplace_back(insert_time, message, identifier, room);
                if (batch_data.size() % UserData::getInstance().mysqlDBCommitBatchSize == 0) {
                    insertBatchData();  /**< Insert the batch if the size exceeds the threshold */
                }
            } else {
                /** We need to clear the batch since it is not getting cleared because of some reasons */
                batch_data.clear();
            }
        } catch (const MySQLException& e) {
            std::cerr << "Insert Data Error : " << e.what() << std::endl;
        }
    }

    /**
     * Forces insertion of any remaining batch data into the database.
     */
    void flushRemainingData() {
        try {
            if (!batch_data.empty()) {
                insertBatchData();  /**< Insert the remaining data in the batch */
            }
        } catch (const MySQLException& e) {
            std::cerr << "Flush Data Error : " << e.what() << std::endl;
        }
    }

    /**
     * Manually creates a connection to the database.
     */
    void manualCreateConnection() {
        try {
            createConnection();  /**< Manually create a connection to the database */
        } catch (const MySQLException& e) {
            std::cerr << "Manual Connection Error : " << e.what() << std::endl;
        }
    }

    /**
     * Disconnects the MySQL connection.
     */
    void disconnect() {
        try {
            if (conn) {
                mysql_close(conn);  /**< Close the connection */
                conn = NULL;
            }
        } catch (const MySQLException& e) {
            std::cerr << "Disconnect Error : " << e.what() << std::endl;
        }
    }
};

class FileWriter {
public:
    /**
     * Constructor to initialize the FileWriter.
     * Opens the file and maps the initial memory chunk.
     * 
     * @param fileName The name of the file to write to.
     * @param initialChunkSize The size of each memory-mapped chunk.
     */
    FileWriter(const char* fileName, size_t initialChunkSize) : fileName(fileName), chunkSize(initialChunkSize), currentOffset(0) {
        
        size_t pageSize = sysconf(_SC_PAGE_SIZE);
        chunkSize = ((chunkSize + pageSize - 1) / pageSize) * pageSize;

        /** Open the file for writing */
        fd = open(fileName, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            throw std::runtime_error("Failed to open file");
        }

        /** Preallocate the file */
        if (ftruncate(fd, chunkSize) == -1) {
            close(fd);
            throw std::runtime_error("Failed to set file size");
        }

        /** Map the initial chunk of the file into memory */
        mapFile();
    }

    /**
     * Destructor to clean up resources.
     * Ensures that the memory is flushed, unmapped, and the file is closed.
     */
    ~FileWriter() {
        try {
            flushAndUnmap();
        } catch (...) {
            /** Ignore errors in the destructor */
        }
        close(fd);
    }

    /**
     * Writes a message to the file using the memory-mapped region.
     * Automatically handles remapping if the current chunk is full.
     * 
     * @param message The message to write.
     */
    void writeMessage(const std::string& message) {
        /** Lock the mutex for thread safety */
        std::lock_guard<std::mutex> lock(mutex);

        /** Calculate the message size and remaining space in the chunk */
        size_t messageSize = message.size();
        size_t remainingSpace = chunkSize - currentOffset;

        /** Check if the message fits in the current chunk */
        if (messageSize > remainingSpace) {
            /** Write the portion that fits in the current chunk */
            if (remainingSpace > 0) {
                std::memcpy(static_cast<char*>(mappedMemory) + currentOffset, message.c_str(), remainingSpace);
                currentOffset += remainingSpace;
                messageSize -= remainingSpace;
            }

            /** Flush and remap to a new chunk */
            flushAndRemap();

            /** Reset offset for the new chunk */
            currentOffset = 0;

            /** Ensure the remaining message fits in the new chunk */
            if (messageSize > chunkSize) {
                throw std::runtime_error("Message too large to fit in a single chunk");
            }
        }

        /** Write the remaining message to the mapped region */
        std::memcpy(static_cast<char*>(mappedMemory) + currentOffset, message.c_str(), messageSize);
        currentOffset += messageSize;
    }

private:
    /**
     * Maps a chunk of the file into memory.
     * Throws an exception if the mapping fails.
     */
    void mapFile() {
        mappedMemory = mmap(nullptr, chunkSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, totalFileOffset);
        if (mappedMemory == MAP_FAILED) {
            std::string err = "Failed to map file at offset " + std::to_string(totalFileOffset) + ": " + std::string(strerror(errno));
            throw std::runtime_error(err);
        }
    }

    /**
     * Unmaps the currently mapped file region.
     * Throws an exception if unmapping fails.
     */
    void unmapFile() {
        if (mappedMemory && munmap(mappedMemory, chunkSize) == -1) {
            throw std::runtime_error("Failed to unmap memory");
        }
        mappedMemory = nullptr;
    }

    /**
     * Flushes changes to disk and remaps the next chunk of the file.
     * Automatically extends the file size as needed.
     */
    void flushAndRemap() {
        /** Flush and unmap the current memory-mapped region */
        flushAndUnmap();

        /** Advance the file offset for the next chunk */
        totalFileOffset += chunkSize;

        /** Extend the file size to accommodate the next chunk */
        if (ftruncate(fd, totalFileOffset + chunkSize) == -1) {
            throw std::runtime_error("Failed to extend file");
        }

        /** Map the next chunk into memory */
        mapFile();
    }

    /**
     * Flushes changes to disk and unmaps the current memory region.
     * Throws an exception if flushing or unmapping fails.
     */
    void flushAndUnmap() {
        /** Synchronize the memory-mapped region with the file */
        if (msync(mappedMemory, currentOffset, MS_SYNC) == -1) {
            throw std::runtime_error("Failed to sync memory to disk");
        }

        /** Unmap the current region */
        unmapFile();
    }

    /** The name of the file to write to */
    const char* fileName;

    /** File descriptor for the opened file */
    int fd;

    /** The size of each memory-mapped chunk */
    size_t chunkSize;

    /** The current write offset within the mapped region */
    size_t currentOffset;

    /** The total offset within the entire file */
    size_t totalFileOffset = 0;

    /** Pointer to the memory-mapped region */
    void* mappedMemory = nullptr;

    /** Mutex for thread safety */
    std::mutex mutex;
};

class GlobalFileWriter {
public:
    static FileWriter& getInstance() {
        static FileWriter instance("output.txt", 10 * 1024);
        return instance;
    }
};

/******************************************************************************************************************************************************************************/

/**HTTP Response */
struct HTTPResponse {
    std::string body;
    int status;
};

/* ws->getUserData returns one of these */
struct PerSocketData {
    /* Define your user data */
    std::string key;
    std::string uid;

    /**
     * true - sending allowed
     * false - sending not allowed
     */
    bool sendingAllowed = true;
};

/** uWebSocket worker runs in a separate thread */
struct worker_t
{
  void work();
  
  /* uWebSocket worker listens on separate port, or share the same port (works on Linux). */
  struct us_listen_socket_t *listen_socket_;

  /* Every thread has its own Loop, and uWS::Loop::get() returns the Loop for current thread.*/
  struct uWS::Loop *loop_;

  /** Every thread has it's own db_handler */
  std::shared_ptr<MySQLConnectionHandler> db_handler;

  /* Need to capture the uWS::App object (instance). */
  std::shared_ptr<uWS::SSLApp> app_;

  /* Thread object for uWebSocket worker */
  std::shared_ptr<std::thread> thread_;
};

/******************************************************************************************************************************************************************************************/

/** Global variables */ 
MDB_env* env;

/** Mutexes for thread-safety */
std::mutex write_mutex;
std::mutex rateLimitMutex;
std::mutex write_worker_mutex;

/** webhooks */
enum class Webhooks : uint8_t {  
    /** Message-related events */
    ON_MESSAGE = 1 << 1,                      /** value 2 */

    /** Connection verification events */
    ON_VERIFICATION_REQUEST = 1 << 2,          /** value 4 */

    /** Connection open events */
    ON_SUBSCRIBE = 1 << 3,               /** value 8 */

    /** Connection close events */
    ON_UNSUBSCRIBE = 1 << 4,              /** value 16 */

    /** Room occupancy events */
    ON_ROOM_OCCUPIED = 1 << 5,                 /** value 32 */

    /** Room vacancy events */
    ON_ROOM_VACATED = 1 << 6                   /** value 64 */
};

/** Features */
enum class Features : uint32_t {
    ENABLE_MYSQL_INTEGRATION = 1 << 0,
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

/** stores data for websocket and its worker for later use */
struct WebSocketData {
    uWS::WebSocket<true, true, PerSocketData>* ws;
    worker_t* worker; 
};

/** Global atomic variables and data structures (all thread safe) */
/** these variables mainly stores the metrics */
std::atomic<int> globalConnectionCounter(0);
std::atomic<unsigned long long> globalMessagesSent{0}; 
std::atomic<unsigned long long> totalPayloadSent{0};
std::atomic<unsigned long long> totalConnectionErrors{0}; /** Websocket connections rejected due to some error */
std::atomic<unsigned long long> totalFailedApiCalls{0}; /** API calls rejected due to 4XX or 5XX codes */
std::atomic<unsigned long long> totalSuccessApiCalls{0}; /** API calls with 2XX code */
std::atomic<unsigned long long> totalLMDBWrites{0}; /** Total writes to the LMDB database */
std::atomic<unsigned long long> totalSuccessWebhookCalls{0}; /** Total webhook calls */
std::atomic<unsigned long long> totalFailedWebhookCalls{0}; /** Total failed webhook calls */
std::atomic<int> totalLatency{0}; /** Total latency in milliseconds */
std::atomic<int> latencyCount(0); /** Number of latency measurements */
std::atomic<unsigned long long> droppedMessages{0};
std::atomic<unsigned int> messageCount(0);
std::atomic<bool> isMessagingDisabled(false);

bool isMultiThread = false;

/** This will be used when the number of threads will be more than 1 */
namespace ThreadSafe {
    /** Thread-safe variables using TBB */
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> topics;
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> bannedConnections;
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> disabledConnections;
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>> uidToRoomMapping;
    tbb::concurrent_hash_map<std::string, bool> uid;
    tbb::concurrent_hash_map<std::string, WebSocketData> connections;
}

/** This will be used when the number of threads will be one */
namespace SingleThreaded {
    /** Non-thread-safe variables using std::unordered_map */
    std::unordered_map<std::string, std::unordered_set<std::string>> topics;
    std::unordered_map<std::string, std::unordered_set<std::string>> bannedConnections;
    std::unordered_map<std::string, std::unordered_set<std::string>> disabledConnections;
    std::unordered_map<std::string, std::unordered_map<std::string, uint8_t>> uidToRoomMapping;
    std::unordered_map<std::string, bool> uid;
    std::unordered_map<std::string, WebSocketData> connections;
}

/** map to store enabled webhooks and features (no need to make it thread safe) */
std::unordered_map<Webhooks, int> webhookStatus;
std::shared_mutex webhookMutex; /** shared mutex for webhook */

std::unordered_map<Features, int> featureStatus;
std::shared_mutex featureMutex; /** shared mutex for features */

/* uWebSocket workers. */
std::vector<worker_t> workers;

/** cooldown timer */
std::atomic<std::chrono::steady_clock::time_point> globalCooldownEnd(std::chrono::steady_clock::now());

/** Configuration parameters */ 
constexpr double k = 0.05;      /** Scaling factor */ 
constexpr double M = 1000.0;    /** Normalization constant for payload size */ 

/** Thread local variables */
thread_local boost::asio::io_context io_context;                                                           // Thread-local io_context
thread_local boost::asio::ssl::context ssl_context(boost::asio::ssl::context::sslv23);                     // Thread-local ssl_context
thread_local std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> ssl_socket = nullptr; // Thread-local ssl_socket
thread_local double localEma = 0.0;

/** Internal Constants */
constexpr const char* INTERNAL_IP = "169.254.169.254";
constexpr const char* MASTER_SERVER_URL = "master.socketlink.io";
constexpr const char* SECRET = "406$%&88767512673QWEdsf379254196073524";
constexpr const int PORT = 443;

/** Sending Constants */
constexpr const char* ACCESS_DENIED = "Access Denied";
constexpr const char* ROOM_NAME_INVALID = "ROOM_NAME_INVALID";
constexpr const char* API_KEY_INVALID = "API_KEY_INVALID";
constexpr const char* CONNECTION_LIMIT_EXCEEDED = "CONNECTION_LIMIT_EXCEEDED";
constexpr const char* DAILY_MSG_LIMIT_EXHAUSTED = "DAILY_MSG_LIMIT_EXHAUSTED";
constexpr const char* SOMEONE_JOINED_THE_ROOM = "SOMEONE_JOINED_THE_ROOM";
constexpr const char* CONNECTED_TO_ROOM = "CONNECTED_TO_ROOM";
constexpr const char* SOMEONE_LEFT_THE_ROOM = "SOMEONE_LEFT_THE_ROOM";
constexpr const char* MESSAGE_SIZE_EXCEEDED = "MESSAGE_SIZE_EXCEEDED";
constexpr const char* YOU_ARE_RATE_LIMITED = "YOU_ARE_RATE_LIMITED";
constexpr const char* RATE_LIMIT_LIFTED = "RATE_LIMIT_LIFTED";    
constexpr const char* BROADCAST = "SOCKETLINK_BROADCAST";
constexpr const char* YOU_HAVE_BEEN_BANNED = "YOU_HAVE_BEEN_BANNED";

/** HMAC-SHA256 Constants */
constexpr int HMAC_SHA256_DIGEST_LENGTH = 32;  /**< SHA-256 produces a 32-byte (256-bit) output */

/** smoothing factor */
constexpr double alpha = 0.05;

/** Create an alias for the json object */
using json = nlohmann::json;  

/****************************************************************************************************************************************************************/

/**
 * Computes the HMAC-SHA256 hash of the given data using the provided key.
 *
 * @param key      The secret key for HMAC.
 * @param key_len  The length of the key in bytes.
 * @param data     The input message to hash.
 * @param data_len The length of the input message in bytes.
 * @param output   A 32-byte buffer to store the computed HMAC.
 */
void hmac_sha256(const char* key, size_t key_len, const char* data, size_t data_len, unsigned char output[HMAC_SHA256_DIGEST_LENGTH]) {
    HMAC_CTX* ctx = HMAC_CTX_new();  /**< Allocate a new HMAC context */
    
    HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), nullptr);  /**< Initialize HMAC with key and SHA-256 */
    HMAC_Update(ctx, (unsigned char*)data, data_len);        /**< Process input data */
    
    unsigned int out_len = 0;  /**< Variable to hold the output length */
    HMAC_Final(ctx, output, &out_len);  /**< Finalize and store result */
    
    HMAC_CTX_free(ctx);  /**< Free the HMAC context */
}

/**
 * Converts binary data to a hexadecimal string representation.
 *
 * @param data Pointer to the binary data.
 * @param len  Length of the binary data in bytes.
 * @return     A string containing the hexadecimal representation.
 */
std::string to_hex(const unsigned char* data, size_t len) {
    static const char hex_digits[] = "0123456789abcdef";  /**< Lookup table for hex conversion */
    
    std::string hex(len * 2, ' ');  /**< Preallocate string for performance */
    for (size_t i = 0; i < len; ++i) {
        hex[2 * i] = hex_digits[(data[i] >> 4) & 0xF];   /**< Extract upper 4 bits */
        hex[2 * i + 1] = hex_digits[data[i] & 0xF];      /**< Extract lower 4 bits */
    }
    
    return hex;  /**< Return hex string */
}

/** Fetch the current time in SQL compatible format */
std::string getCurrentSQLTime() {
    /** Get the current time as a time_point */
    auto now = std::chrono::system_clock::now();
    
    /** Convert time_point to system_time, which represents seconds since epoch */
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    
    /** Convert to a tm struct (UTC time) */
    std::tm tm = *std::gmtime(&now_c);  /** Use UTC time instead of local time */
    
    /** Buffer to hold the formatted time string */
    char buffer[20]; /** 'YYYY-MM-DD HH:MM:SS' format */

    /** Use strftime to format the time string */
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
    
    return std::string(buffer);
}

/** Initialize LMDB environment */ 
void init_env() {
    if (mdb_env_create(&env) != 0) {
        std::cerr << "Failed to create LMDB environment.\n";
        exit(-1);
    }

    /** map size is 10 GB */
    if (mdb_env_set_mapsize(env, UserData::getInstance().lmdbDatabaseSizeInBytes) != 0) { 
        std::cerr << "Failed to set map size.\n";
        exit(-1);
    }

    if (mdb_env_set_maxreaders(env, 128) != 0) {
        std::cerr << "Failed to set max readers.\n";
        exit(-1);
    }

    if (mdb_env_set_maxdbs(env, 1) != 0) {
        std::cerr << "Failed to set max databases.\n";
        exit(-1);
    }

    if (mdb_env_open(env, "./messages_db", MDB_WRITEMAP, 0664) != 0) {
        std::cerr << "Failed to open LMDB environment.\n";
        exit(-1);
    }

    std::cout << "Environment initialized successfully.\n";
}

/** write the data to the LMDB, LMDB has internal locking mechanish so no need to mutexes */
void write_worker(const std::string& room_id, const std::string& message_content, bool needsCommit = false) {
    MDB_txn* txn;
    MDB_dbi dbi;

    /** Batch to store messages before writing them to the database */
    thread_local std::vector<std::tuple<std::string, std::string>> batch;

    /** Collect writes in a batch if commit is not immediately required */
    if (!needsCommit) {
        /** Add the key-value pair to the batch */
        batch.push_back({room_id, message_content});
    }

    /** Begin a write transaction when batch size reaches limit or a commit is explicitly needed */
    if (batch.size() >= UserData::getInstance().lmdbCommitBatchSize || (needsCommit && batch.size() > 0)) {
        /** Begin a new write transaction */
        if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
            std::cerr << "Failed to begin write transaction.\n";
            batch.clear();  // Clear batch on error
            return;
        }

        /** Open the database (common for all rooms) */
        if (mdb_dbi_open(txn, "messages_db", MDB_CREATE, &dbi) != 0) {
            std::cerr << "Failed to open database.\n";
            batch.clear();  // Clear batch on error
            mdb_txn_abort(txn);
            return;
        }

        /** Write each key-value pair from the batch into the database */
        for (const auto& [key_str, value_str] : batch) {
            MDB_val key, value;

            /** Prepare the key */
            key.mv_size = key_str.size();
            key.mv_data = (void*)key_str.data();

            /** Prepare the value */
            value.mv_size = value_str.size();
            value.mv_data = (void*)value_str.data();

            /** Insert the key-value pair into the database */
            if (mdb_put(txn, dbi, &key, &value, 0) != 0) {
                std::cerr << "Write failed.\n";
                batch.clear();  // Clear batch on error
                mdb_txn_abort(txn);
                return;
            }
        }

        /** Commit the transaction after writing the batch */
        if (mdb_txn_commit(txn) != 0) {
            std::cerr << "Failed to commit transaction.\n";
            batch.clear();  // Clear batch on error
            mdb_txn_abort(txn);
            return;
        }

        /** Clear the batch after a successful commit */
        batch.clear();

        /** Close the database handle */
        mdb_dbi_close(env, dbi);
    }
}

/** This function will delete the entry stored under the exact room_id key */
void delete_worker(const std::string& room_id) {
    MDB_txn* txn;
    MDB_dbi dbi;
    MDB_val key;

    /** Lock the mutex to ensure thread-safety for shared resources */
    std::lock_guard<std::mutex> lock(write_worker_mutex);

    /** Begin a write transaction */
    if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
        std::cerr << "Failed to begin delete transaction.\n";
        return;
    }

    /** Open the database */
    if (mdb_dbi_open(txn, "messages_db", 0, &dbi) != 0) {
        std::cerr << "Failed to open database.\n";
        mdb_txn_abort(txn);
        return;
    }

    /** Set up the key for deletion */
    key.mv_data = (void*)room_id.c_str();
    key.mv_size = room_id.size();

    /** Delete the entry with the exact room_id key */
    if (mdb_del(txn, dbi, &key, nullptr) != 0) {
        std::cerr << "Failed to delete key: " << room_id << "\n";
        mdb_txn_abort(txn);
        return;
    }

    /** Commit the transaction after deletion */
    if (mdb_txn_commit(txn) != 0) {
        std::cerr << "Failed to commit delete transaction.\n";
    }

    /** Close database handle */
    mdb_dbi_close(env, dbi);
}

std::string read_worker(const std::string& room_id) {
    MDB_txn* txn;  /** Transaction handle */
    MDB_dbi dbi;   /** Database handle */
    MDB_val key, value;  /** Key-value pair to store the retrieved data */

    /** Start a read-only transaction */
    if (mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn) != 0) {
        std::cerr << "Failed to begin read transaction: " << mdb_strerror(errno) << "\n";
        return "{}";  /** Return empty JSON object on failure */
    }

    /** Open the common database for all rooms */
    if (mdb_dbi_open(txn, "messages_db", 0, &dbi) != 0) {
        std::cerr << "Failed to open database: " << mdb_strerror(errno) << "\n";
        mdb_txn_abort(txn);
        return "{}";  /** Return empty JSON object on failure */
    }

    /** Prepare the key (room_id) */
    key.mv_size = room_id.size();
    key.mv_data = (void*)room_id.data();

    /** Retrieve the value for the given room_id */
    if (mdb_get(txn, dbi, &key, &value) == 0) {
        std::string message_content((char*)value.mv_data, value.mv_size);
        
        /** Construct the JSON response */
        /* std::ostringstream result;
        result << "{\n";
        result << "  \"message\": \"" << message_content << "\"\n";
        result << "}"; */

        /** Close the database handle and commit transaction */
        mdb_dbi_close(env, dbi);
        mdb_txn_commit(txn);

        /* return result.str(); */
        return message_content;
    }

    /** No message found for the given room_id */
    std::cerr << "No message found for room_id: " << room_id << "\n";
    mdb_dbi_close(env, dbi);
    mdb_txn_abort(txn);
    return "{}";  /** Return empty JSON object if no message exists */
}

/** Function to populate the global unordered_map with active (1) and inactive (0) statuses */
void populateWebhookStatus(uint8_t bitmask)
{
    std::unique_lock<std::shared_mutex> lock(webhookMutex); /** Exclusive lock for writing */

    for (uint8_t i = 0; i < 6; ++i)  /** Use uint8_t to match bitmask size */ 
    {
        /** Compute the webhook flag for this index */
        Webhooks webhook = static_cast<Webhooks>(static_cast<uint8_t>(1) << i);
        
        /** Store the webhook status based on the bitmask */
        webhookStatus[webhook] = (bitmask & (static_cast<uint8_t>(1) << i)) ? 1 : 0;
    }
}

/** read webhooks, thread safe */
int getWebhookStatus(Webhooks webhook)
{
    std::shared_lock<std::shared_mutex> lock(webhookMutex); /** Shared lock for reading */ 

    auto it = webhookStatus.find(webhook);
    return (it != webhookStatus.end()) ? it->second : 0; /** Return 0 if not found */ 
}

/** Populate the enabled features */
void populateFeatureStatus(uint32_t bitmask)
{
    std::unique_lock<std::shared_mutex> lock(featureMutex);  /** Exclusive lock for writing */ 

    for (uint32_t i = 0; i < 1; ++i)
    {
        Features feature = static_cast<Features>(1 << i);
        featureStatus[feature] = (bitmask & (1 << i)) ? 1 : 0;
    }
}

/** read features, thread safe */
int getFeatureStatus(Features feature)
{
    std::shared_lock<std::shared_mutex> lock(featureMutex);  /** Shared lock for reading */ 

    auto it = featureStatus.find(feature);
    return (it != featureStatus.end()) ? it->second : 0;
}

/**
 * @brief Send an HTTP request to the given URL and path
 */
HTTPResponse sendHTTPRequest(std::string baseURL, std::string path, const httplib::Headers& headers = {}) {
    try
    {
        /** Create an HTTP client for the IP service */ 
        httplib::Client client(baseURL); 

        /** Make a GET request (no additional path needed for ipify) */ 
        auto res = client.Get(path, headers);

        /** Check if the response is valid */ 
        if (res && res->status == 200) {
            return {res->body, res->status};
        } else {
            return {"", -1};
        }
    }
    catch(const std::exception& e)
    {
        return {"", -1};
    }
}

/**
 * @brief Send an HTTPS POST request to the given URL and path
 */
HTTPResponse sendHTTPSPOSTRequest(
    std::string baseURL, std::string path, 
    const std::string& body, 
    const httplib::Headers& headers = {}
) {
    try
    {
        /** Create an HTTPS client for the IP service */ 
        httplib::SSLClient client(baseURL); 

        /** Make a POST request with body and headers */ 
        auto res = client.Post(path.c_str(), headers, body, "application/json");

        /** Check if the response is valid */ 
        if (res && res->status == 200) {
            return {res->body, res->status};
        } else {
            return {"", res ? res->status : -1};
        }
    }
    catch(const std::exception& e)
    {
        return {"", -1};
    }
}

/** send a FIRE-AND-FOREGET http post request for webhook */
int sendHTTPSPOSTRequestFireAndForget(
    const std::string& baseURL, 
    const std::string& path, 
    const std::string& body, 
    const std::map<std::string, std::string>& headers = {},
    bool waitForResponse = false
) {
    for (int attempt = 0; attempt < 2; ++attempt) {
        try {
            /** Disable SSL certificate verification if needed. 
             *  This is insecure and should only be used for testing purposes. */
            if(UserData::getInstance().webhookIP.empty()){
                /** DNS is not resolved, returning */
                return 0;
            }

            ssl_context.set_verify_mode(boost::asio::ssl::verify_none);

            if (!ssl_socket || !ssl_socket->lowest_layer().is_open()) {  
                ssl_socket = std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(io_context, ssl_context);
                
                /** if the request cannot be delivered immediately it will be dropped */
                /* ssl_socket->lowest_layer().non_blocking(true); */  

                /** Specify the endpoint using the IP address and port. 
                 *  Ensure the IP address is correctly formatted. */
                boost::asio::ip::tcp::endpoint endpoint(
                    boost::asio::ip::make_address(UserData::getInstance().webhookIP),
                    443
                );

                /** Establish a connection to the endpoint. */
                ssl_socket->lowest_layer().connect(endpoint);
                
                boost::asio::socket_base::keep_alive keepAliveOption(true);
                ssl_socket->lowest_layer().set_option(keepAliveOption);

                /** Perform the SSL handshake. */
                ssl_socket->handshake(boost::asio::ssl::stream_base::client);
            }

            /** Enable the TCP no-delay option to minimize latency. */
            boost::asio::ip::tcp::no_delay no_delay_option(true);
            ssl_socket->lowest_layer().set_option(no_delay_option);

            /** Prepare a buffer for the HTTP request using boost::asio::streambuf. 
             *  This ensures efficient memory management. */
            boost::asio::streambuf request_buffer;
            std::ostream request_stream(&request_buffer);

            if(UserData::getInstance().webhookSecret.length() > 0) {
                unsigned char hmac_result[HMAC_SHA256_DIGEST_LENGTH];  /**< Buffer to store the HMAC result */
                hmac_sha256(UserData::getInstance().webhookSecret.c_str(), strlen(UserData::getInstance().webhookSecret.c_str()), body.c_str(), body.length(), hmac_result);  /**< Compute HMAC */
                            
                /** Construct the HTTP request headers with hmac */
                request_stream << "POST " << path << " HTTP/1.1\r\n"
                << "Host: " << baseURL << "\r\n"
                << "Connection: keep-alive\r\n"
                << "Content-Type: application/json\r\n"
                << "X-HMAC-Signature: " << to_hex(hmac_result, HMAC_SHA256_DIGEST_LENGTH) << "\r\n";  /**< Include HMAC in headers */
            } else {
                /** Construct the HTTP request headers without hmac */
                request_stream << "POST " << path << " HTTP/1.1\r\n"
                << "Host: " << baseURL << "\r\n"
                << "Connection: keep-alive\r\n"
                << "Content-Type: application/json\r\n";
            }
            
            /** Add any custom headers provided as a map. */
            for (const auto& header : headers) {
                request_stream << header.first << ": " << header.second << "\r\n";
            }

            /** Specify the content length and finalize the headers. */
            request_stream << "Content-Length: " << body.size() << "\r\n" << "\r\n";

            /** Send the request headers over the SSL socket. */
            boost::asio::write(*ssl_socket, request_buffer); 

            /** Send the request body over the SSL socket. */
            boost::asio::write(*ssl_socket, boost::asio::buffer(body)); 

            /** Properly shut down and close the connection. */
            /* ssl_socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            ssl_socket->lowest_layer().close();

            ssl_socket = nullptr; */

            if (waitForResponse) {
                boost::asio::streambuf response_buffer;
                boost::system::error_code ec;
            
                /** Read until the full headers are received */
                boost::asio::read_until(*ssl_socket, response_buffer, "\r\n\r\n", ec);
            
                if (!ec) {
                    std::istream response_stream(&response_buffer);
                    std::string status_line;
                    
                    /** Read the first line containing HTTP status */
                    std::getline(response_stream, status_line);
            
                    /** Ensure the line is properly read */
                    if (status_line.empty()) {
                        log("Error : Empty response line!");
                        return 0;
                    }
            
                    /** Extract HTTP version, status code, and status message */
                    std::istringstream status_stream(status_line);
                    std::string http_version;
                    unsigned int status_code;
                    std::string status_message;
            
                    status_stream >> http_version >> status_code;
                    std::getline(status_stream, status_message);
            
                    /** Trim leading spaces from status_message */
                    if (!status_message.empty() && status_message.front() == ' ') {
                        status_message.erase(0, 1);
                    }

                    /** increment success webhook calls */
                    totalSuccessWebhookCalls.fetch_add(1, std::memory_order_relaxed);
                        
                    return status_code;
                } else {
                    log("Error reading response : " + ec.message());
                    return 0;
                }
            }

            /** increment success webhook calls */
            totalSuccessWebhookCalls.fetch_add(1, std::memory_order_relaxed);

            break;
        } catch (const boost::system::system_error& e) {
            log("Error in sendHTTPSPOSTRequestFireAndForget : " + std::string(e.what()));

            ssl_socket = nullptr;

            /*** Retry only once on failure ***/
            if (attempt == 1) {
                /** increment failed webhook calls */
                totalFailedWebhookCalls.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
    }

    return 0;
}

/**
 * @brief Send an HTTPS request to the given URL and path
 */
HTTPResponse sendHTTPSRequest(std::string baseURL, std::string path, const httplib::Headers& headers = {}) {
    try
    {
        /** Create an HTTPS client for the IP service */ 
        httplib::SSLClient client(baseURL); 

        /** Make a GET request (no additional path needed for ipify) */ 
        auto res = client.Get(path, headers);

        /** Check if the response is valid */ 
        if (res && res->status == 200) {
            return {res->body, res->status};
        } else {
            return {"", -1};
        }
    }
    catch(const std::exception& e)
    {
        return {"", -1};
    }
}

/**
 * Resolves the IPv4 address for the given hostname and stores it.
 * This function ensures proper memory management and handles errors gracefully.
 * 
 * @param hostname The domain name to resolve (e.g., "www.example.com").
 */
void resolveAndStoreIPAddress(const std::string& hostname) {
    /** Define the hints structure to specify address family and socket type */
    struct addrinfo hints, *res = nullptr;
    char ipAddress[INET_ADDRSTRLEN]; 

    /** Zero out the hints structure */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;        
    hints.ai_socktype = SOCK_STREAM; 

    /** Resolve the hostname to an IP address using getaddrinfo */
    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (status != 0) {
        /** Print an error message if resolution fails */
        std::cerr << "getaddrinfo error : " << gai_strerror(status) << std::endl;
        return;
    }

    /** Extract and convert the IPv4 address to a readable format */
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr; 
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, sizeof(ipAddress)); 

    /** storing the address */
    UserData::getInstance().webhookIP = ipAddress;

    /** Free the allocated memory for the addrinfo structure */
    freeaddrinfo(res);
}

/** This function will parse and populate the userdata */
int populateUserData(std::string data) {    
    nlohmann::json parsedJson = nlohmann::json::parse(data);
    int needsDBUpdate = 0;

    auto& userData = UserData::getInstance();

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

    if (parsedJson.contains("max_monthly_payload_in_bytes") && !parsedJson["max_monthly_payload_in_bytes"].is_null()) {
        userData.maxMonthlyPayloadInBytes = parsedJson["max_monthly_payload_in_bytes"].get<unsigned long long>();
    }

    if (parsedJson.contains("webhooks") && !parsedJson["webhooks"].is_null()) {
        userData.webhooks = parsedJson["webhooks"].get<uint8_t>();

        /** populate enabled webhooks and features */
        populateWebhookStatus(userData.webhooks);
    }

    if (parsedJson.contains("features") && !parsedJson["features"].is_null()) {
        userData.features = parsedJson["features"].get<uint32_t>();
    }

    if (parsedJson.contains("webhook_base_url") && !parsedJson["webhook_base_url"].is_null()) {
        userData.webHookBaseUrl = parsedJson["webhook_base_url"].get<std::string>();

        /** resolve and store the IP address of the client's webhook URL */
        resolveAndStoreIPAddress(userData.webHookBaseUrl);
    }

    if (parsedJson.contains("webhook_path") && !parsedJson["webhook_path"].is_null()) {
        userData.webhookPath = parsedJson["webhook_path"].get<std::string>();
    }

    if (parsedJson.contains("webhook_secret") && !parsedJson["webhook_secret"].is_null()) {
        userData.webhookSecret = parsedJson["webhook_secret"].get<std::string>();
    }

    if(parsedJson.contains("max_storage_allowed_in_gb") && !parsedJson["max_storage_allowed_in_gb"].is_null()){
        userData.lmdbDatabaseSizeInBytes = parsedJson["max_storage_allowed_in_gb"].get<unsigned long long>() * 1024ULL * 1024 * 1024;
    }

    if(parsedJson.contains("lmdb_commit_batch_size") && !parsedJson["lmdb_commit_batch_size"].is_null()){
        userData.lmdbCommitBatchSize = parsedJson["lmdb_commit_batch_size"].get<int>();
    }

    if(parsedJson.contains("db_commit_batch_size") && !parsedJson["db_commit_batch_size"].is_null()){
        userData.mysqlDBCommitBatchSize = parsedJson["db_commit_batch_size"].get<int>();
    }

    if(parsedJson.contains("idle_timeout_in_seconds") && !parsedJson["idle_timeout_in_seconds"].is_null()){
        unsigned short idleTimeoutInSeconds = parsedJson["idle_timeout_in_seconds"].get<unsigned short>();
        if(userData.idleTimeoutInSeconds == 60 && idleTimeoutInSeconds != userData.idleTimeoutInSeconds){
            userData.idleTimeoutInSeconds = idleTimeoutInSeconds;
        } else {
            userData.idleTimeoutInSeconds = idleTimeoutInSeconds;
            needsDBUpdate = 2;
        }
    }

    if(parsedJson.contains("max_lifetime_in_minutes") && !parsedJson["max_lifetime_in_minutes"].is_null()){
        unsigned short maxLifetimeInMinutes = parsedJson["max_lifetime_in_minutes"].get<unsigned short>();
        if(userData.maxLifetimeInMinutes == 0 && maxLifetimeInMinutes != userData.maxLifetimeInMinutes){
            userData.maxLifetimeInMinutes = maxLifetimeInMinutes;
        } else {
            userData.maxLifetimeInMinutes = maxLifetimeInMinutes;
            needsDBUpdate = 2;
        }
    }

    if(parsedJson.contains("max_backpressure_in_bytes") && !parsedJson["max_backpressure_in_bytes"].is_null()){
        userData.maxBackpressureInBytes = parsedJson["max_backpressure_in_bytes"].get<unsigned int>();
    }

    if(parsedJson.contains("subdomain") && !parsedJson["subdomain"].is_null()){
        userData.subdomain = parsedJson["subdomain"].get<std::string>();
    }

    if(parsedJson.contains("ip") && !parsedJson["ip"].is_null()){
        userData.ip = parsedJson["ip"].get<std::string>();
    }

    /** populate features */
    populateFeatureStatus(UserData::getInstance().features);

    int is_sql_integration_enabled = 0;

    /** check if sql integration is enabled */
    if (parsedJson.contains("is_sql_integration_enabled") && !parsedJson["is_sql_integration_enabled"].is_null()) {
        if (parsedJson["is_sql_integration_enabled"].get<bool>())
        {
            is_sql_integration_enabled = 1;
        }
        else
        {
            is_sql_integration_enabled = -1;
        }
    }

    std::string dbHost = "";
    std::string dbUser = "";
    std::string dbPassword = "";
    std::string dbName = "";
    int dbPort = 0;

    /** Store db data */
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

    /** Enable SQL Integration feature */
    if(
        dbHost.length() > 0
        && dbUser.length() > 0
        && dbPassword.length() > 0
        && dbName.length() > 0
        && dbPort != 0
    ){
        if (
            UserData::getInstance().dbHost != dbHost 
            || UserData::getInstance().dbUser != dbUser
            || UserData::getInstance().dbPassword != dbPassword
            || UserData::getInstance().dbName != dbName
            || UserData::getInstance().dbPort != dbPort
        ){
            userData.dbHost = dbHost;
            userData.dbUser = dbUser;
            userData.dbPassword = dbPassword;
            userData.dbName = dbName;
            userData.dbPort = dbPort;
        } 
    }

    if (is_sql_integration_enabled == 1)
    {
        std::unique_lock<std::shared_mutex> lock(featureMutex);
        featureStatus[Features::ENABLE_MYSQL_INTEGRATION] = 1;
        needsDBUpdate = 1;
    }
    else if (is_sql_integration_enabled == -1)
    {
        std::unique_lock<std::shared_mutex> lock(featureMutex);
        featureStatus[Features::ENABLE_MYSQL_INTEGRATION] = 0;
        needsDBUpdate = -1;
    }

    /** store payload sent */
    if (parsedJson.contains("total_payload_sent")) {
        totalPayloadSent = parsedJson["total_payload_sent"].get<unsigned long long>();
    }

    return needsDBUpdate;
}

/**
 * @brief Fetch and populate user data from the metadata service
 */
void fetchAndPopulateUserData() {
    try {
        std::string dropletId = sendHTTPRequest(INTERNAL_IP, "/metadata/v1/id").body;

        unsigned char hmac_result[HMAC_SHA256_DIGEST_LENGTH];  /**< Buffer to store the HMAC result */
        hmac_sha256(SECRET, strlen(SECRET), dropletId.c_str(), dropletId.length(), hmac_result);  /**< Compute HMAC */
            
        /** Make the HTTP request */ 
        std::string userData = sendHTTPSRequest(MASTER_SERVER_URL, "/api/v1/init/" + dropletId, {
            {"secret", to_hex(hmac_result, HMAC_SHA256_DIGEST_LENGTH)}
        }).body;

        /** populate the userdata */
        populateUserData(userData);
    } catch (const nlohmann::json::parse_error& e) {
        /**  Handle JSON parsing errors */
        std::cerr << "JSON Parse Error : " << e.what() << std::endl;
    } catch (const nlohmann::json::type_error& e) {
        /** Handle type mismatches in the JSON */ 
        std::cerr << "JSON Type Error : " << e.what() << std::endl;
    } catch (const std::exception& e) {
        /** Catch any other standard exceptions */ 
        std::cerr << "Exception : " << e.what() << std::endl;
    } catch (...) {
        /** Catch any unknown exceptions */ 
        std::cerr << "An unknown error occurred." << std::endl;
    }
}

/** unsubscribe from the current room and do some cleanup */
void closeConnection(uWS::WebSocket<true, true, PerSocketData>* ws, worker_t* worker, std::string rid, std::string uid, uint8_t roomType, bool isClosed = false) {
    if(isClosed == false){
        /** removing the RID from the uid_to_rid mapping */
        if(isMultiThread) {
            tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor uid_to_rid_outer_accessor;
            if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, ws->getUserData()->uid)) {
                auto& inner_uid_to_rid_map = uid_to_rid_outer_accessor->second;

                /** Remove the rid from the inner map */
                {
                    tbb::concurrent_hash_map<std::string, uint8_t>::accessor uid_to_rid_inner_accessor;
                    if (inner_uid_to_rid_map.find(uid_to_rid_inner_accessor, rid)) {
                        inner_uid_to_rid_map.erase(uid_to_rid_inner_accessor);
                    }
                }

                /** Check if the inner map is now empty */
                if (inner_uid_to_rid_map.empty()) {

                    /** Check if the uid map has the value false, make it true (orphan) else ignore */
                    tbb::concurrent_hash_map<std::string, bool>::accessor uid_outer_accessor;
                    if (ThreadSafe::uid.find(uid_outer_accessor, ws->getUserData()->uid)) {
                        if (!uid_outer_accessor->second) { 
                            uid_outer_accessor->second = true;
                        }
                    }

                    ThreadSafe::uidToRoomMapping.erase(uid_to_rid_outer_accessor);
                }
            }
        } else {
            if (auto it = SingleThreaded::uidToRoomMapping.find(uid); it != SingleThreaded::uidToRoomMapping.end()) {
                it->second.erase(rid);
                
                if (it->second.empty()) {
                    SingleThreaded::uidToRoomMapping.erase(it);
            
                    if (auto uidIt = SingleThreaded::uid.find(uid); uidIt != SingleThreaded::uid.end() && !uidIt->second) {
                        uidIt->second = true;
                    }
                }
            }                        
        }
    }

    /** Unsubscribe the user from the room */
    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor outer_accessor;

    int size = 0;

    /** Check if the room exists in the topics map */
    if(isMultiThread){
        if (ThreadSafe::topics.find(outer_accessor, rid)) {
            auto& inner_map = outer_accessor->second;

            /** Remove user from the inner map */
            {
                tbb::concurrent_hash_map<std::string, bool>::accessor inner_accessor;
                if (inner_map.find(inner_accessor, ws->getUserData()->uid)) {
                    inner_map.erase(inner_accessor);
                }
            }

            size = inner_map.size();

            /** Remove room if empty */
            if (size == 0) {
                /** Remove room from topics */
                ThreadSafe::topics.erase(outer_accessor);

                /** Remove disabled and banned connections */
                for (auto& map : {&ThreadSafe::disabledConnections, &ThreadSafe::bannedConnections}) {
                    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor map_accessor;

                    if (map->find(map_accessor, rid)) {
                        map->erase(map_accessor);
                    }
                }
            }
        }
    } else {
        auto it = SingleThreaded::topics.find(rid);
        if (it != SingleThreaded::topics.end()) {
            auto& inner_set = it->second; 

            /** Removing the entry from the inner set */
            inner_set.erase(ws->getUserData()->uid);

            /** Store the new size */
            size = inner_set.size();

            /** Remove the room if empty */
            if (size == 0) {
                SingleThreaded::topics.erase(it); 

                /** Remove disabled and banned connections */
                for (auto& map : {&SingleThreaded::disabledConnections, &SingleThreaded::bannedConnections}) {
                    map->erase(rid);
                }
            }
        }
    }
    
    /** Unsubscribe on the correct thread */
    auto unsubscribe_fn = [ws, rid]() { ws->unsubscribe(rid); };
    if (worker->thread_->get_id() != std::this_thread::get_id()) {
        worker->loop_->defer(unsubscribe_fn);
    } else {
        unsubscribe_fn();
    }

    static const std::unordered_set<uint8_t> validCacheRoomTypes = {
        static_cast<uint8_t>(Rooms::PUBLIC_CACHE),
        static_cast<uint8_t>(Rooms::PRIVATE_CACHE),
        static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE),
        static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)
    };

    /** delete the key value pair if it's a cache room */
    if(size == 0 && validCacheRoomTypes.count(roomType)){
        delete_worker(rid);
    }

    /** Broadcast disconnect message */
    static const std::unordered_set<uint8_t> validRoomTypes = {
        static_cast<uint8_t>(Rooms::PUBLIC_STATE),
        static_cast<uint8_t>(Rooms::PRIVATE_STATE),
        static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE),
        static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)
    };

    if (validRoomTypes.count(roomType)) {
        std::string result = "{\"data\":\"SOMEONE_LEFT_THE_ROOM\", \"uid\":\"" + ws->getUserData()->uid + "\", \"source\":\"server\", \"rid\":\"" + rid + "\"}";

        /** Publish message to all workers */
        for (auto& w : ::workers) {
            w.loop_->defer([&w, rid, result]() {
                w.app_->publish(rid, result, uWS::OpCode::TEXT, true);
            });
        }
    }

    if(getWebhookStatus(Webhooks::ON_UNSUBSCRIBE) == 1){
        std::ostringstream payload;
        payload << "{\"event\":\"ON_UNSUBSCRIBE\", "
        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
        << "\"rid\":\"" << rid << "\", "
        << "\"connections_in_room\":\"" << size << "\"}";    

        std::string body = payload.str(); 
        
        sendHTTPSPOSTRequestFireAndForget(
            UserData::getInstance().webHookBaseUrl,
            UserData::getInstance().webhookPath,
            body,
            {}
        );
    }

    /** room vacate webhooks */
    if (size == 0) {
        if(getWebhookStatus(Webhooks::ON_ROOM_VACATED) == 1){
            std::ostringstream payload;
            payload << "{\"event\":\"ON_ROOM_VACATED\", "
            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
            << "\"rid\":\"" << rid << "\"}";             

            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        }
    }
}

/** subscribe to a new room */
void openConnection(uWS::WebSocket<true, true, PerSocketData>* ws, worker_t* worker, std::string rid, uint8_t roomType) {    
    if (!rid.empty()) {
        const auto& uid = ws->getUserData()->uid;
        auto currentThreadId = std::this_thread::get_id();
        auto workerThreadId = worker->thread_->get_id();

        /** Subscribe to the room in the same thread where the ws instance was created */
        if (workerThreadId == currentThreadId) {
            ws->subscribe(rid);
        } else {
            worker->loop_->defer([ws, rid]() {
                ws->subscribe(rid);
            });
        }

        int size = 0;

        if(isMultiThread) {
            /** Acquire an accessor for the outer map (topics) */
            tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor topicsAccessor;
        
            /** Check if the room ID (rid) already exists in the topics map */
            if (ThreadSafe::topics.find(topicsAccessor, rid)) {
                /** Room exists, retrieve the inner map containing user IDs */
                auto& innerMap = topicsAccessor->second;
        
                /** Acquire an accessor for the inner map */
                tbb::concurrent_hash_map<std::string, bool>::accessor innerAccessor;
                
                /** Insert UID into the inner map if not already present */
                if (innerMap.insert(innerAccessor, uid)) {
                    /** Set the value to true, indicating user presence */
                    innerAccessor->second = true;
                }
        
                /** Update the size variable with the total number of users in the room */
                size = innerMap.size();
            } else {
                /** Room does not exist, create a new inner map */
                tbb::concurrent_hash_map<std::string, bool> newInnerMap;
        
                /** Insert the UID into the newly created inner map */
                newInnerMap.emplace(uid, true);
        
                /** Insert the new inner map into the topics map */
                if (ThreadSafe::topics.insert(topicsAccessor, rid)) {
                    /** Move the newly created inner map to avoid unnecessary copies */
                    topicsAccessor->second = std::move(newInnerMap);
                }
        
                /** Since this is a new room, its size is 1 (only the current user) */
                size = 1;
            }
        } else {
            auto [it, inserted] = SingleThreaded::topics.try_emplace(rid);
            auto& inner_set = it->second; 

            /** Insert the user into the inner set */
            inner_set.emplace(std::move(uid));

            /** Store the new size */
            size = inner_set.size();
        }   

        if(isMultiThread) {
            /** Acquire an accessor for the outer map */ 
            tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor uid_to_rid_outer_accessor;
        
            /** Check if UID exists */ 
            if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, uid)) {
                auto& innerMap = uid_to_rid_outer_accessor->second;
                
                /** Acquire an accessor for the inner map */ 
                tbb::concurrent_hash_map<std::string, uint8_t>::accessor uid_to_rid_inner_accessor;

                if (innerMap.insert(uid_to_rid_inner_accessor, rid)) {
                    /** Only set roomType if insertion was successful */ 
                    uid_to_rid_inner_accessor->second = roomType;
                }
            } else {
                if (ThreadSafe::uidToRoomMapping.insert(uid_to_rid_outer_accessor, uid)) {
                    /** Create the new inner map */ 
                    tbb::concurrent_hash_map<std::string, uint8_t>& innerMap = uid_to_rid_outer_accessor->second;
            
                    /** Insert the rid with its roomType */ 
                    tbb::concurrent_hash_map<std::string, uint8_t>::accessor uid_to_rid_inner_accessor;
                    if (innerMap.insert(uid_to_rid_inner_accessor, rid)) {
                        uid_to_rid_inner_accessor->second = roomType;
                    }
                }

                /** Check if the uid map has the value true, make it false else ignore */
                tbb::concurrent_hash_map<std::string, bool>::accessor uid_outer_accessor;
                if (ThreadSafe::uid.find(uid_outer_accessor, uid)) {
                    if (uid_outer_accessor->second) { 
                        uid_outer_accessor->second = false;
                    }
                }
            }
        } else {
            /** Try inserting the UID into uidToRoomMapping */
            auto result = SingleThreaded::uidToRoomMapping.try_emplace(uid);
            result.first->second.emplace(rid, roomType); 

            /** Check if UID exists in SingleThreaded::uid and update if needed */
            if (auto it2 = SingleThreaded::uid.find(uid); it2 != SingleThreaded::uid.end() && it2->second) {
                it2->second = false;
            }
        }   
    
        /** Send a message to self */
        std::string selfMessage = "{\"data\":\"CONNECTED_TO_ROOM\", \"source\":\"server\", \"rid\":\"" + rid + "\"}";

        if (workerThreadId == currentThreadId) {
            ws->send(selfMessage, uWS::OpCode::TEXT, true);
        } else {
            worker->loop_->defer([ws, selfMessage]() {
                ws->send(selfMessage, uWS::OpCode::TEXT, true);
            });
        }

        /** Broadcast the message to others if the room is public/private */
        if (roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE) ||
            roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE) ||
            roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) ||
            roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)) {

            auto sharedBroadcast = std::make_shared<std::string>(
                "{\"data\":\"SOMEONE_JOINED_THE_ROOM\", \"uid\":\"" + uid + 
                "\", \"source\":\"server\", \"rid\":\"" + rid + "\"}"
            );

            for (auto& w : ::workers) {
                if (workerThreadId == w.thread_->get_id()) {
                    ws->publish(rid, *sharedBroadcast, uWS::OpCode::TEXT, true);
                } else {
                    w.loop_->defer([app = w.app_, sharedBroadcast, rid]() {
                        app->publish(rid, *sharedBroadcast, uWS::OpCode::TEXT, true);
                    });
                }
            }
        }

        /** fire connection open webhook */
        if(getWebhookStatus(Webhooks::ON_SUBSCRIBE) == 1){
            std::ostringstream payload;
            payload << "{\"event\":\"ON_SUBSCRIBE\", "
            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
            << "\"rid\":\"" << rid << "\", "
            << "\"connections_in_room\":\"" << size << "\"}";    

            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        }

        /** Room ocuupied webhooks */
        if(size == 1){            
            if(getWebhookStatus(Webhooks::ON_ROOM_OCCUPIED) == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_OCCUPIED\", "
                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                << "\"rid\":\"" << rid << "\"}";             

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            }
        }
    }
}

/** calculate latency for each thread */
void update_ema(double newLatency) {
    localEma = alpha * newLatency + (1 - alpha) * localEma;
}

/* uWebSocket worker thread function. */
void worker_t::work()
{
    const std::string keyFilePath = "/home/socketlink/certbot-config/live/" + UserData::getInstance().subdomain + ".socketlink.io/privkey.pem";
    const std::string certFileName = "/home/socketlink/certbot-config/live/" + UserData::getInstance().subdomain + ".socketlink.io/fullchain.pem";

  /* Every thread has its own Loop, and uWS::Loop::get() returns the Loop for current thread.*/ 
  loop_ = uWS::Loop::get();

  /* uWS::App object / instance is used in uWS::Loop::defer(lambda_function) */
  app_ = std::make_shared<uWS::SSLApp>(
    uWS::SSLApp({
        .key_file_name = keyFilePath.c_str(),
        .cert_file_name = certFileName.c_str(),
        .ssl_prefer_low_memory_usage = 0,
    })
  );

  db_handler = std::make_unique<MySQLConnectionHandler>();

  /* Very simple WebSocket broadcasting echo server */
  app_->ws<PerSocketData>("/*", {
    /* Settings */
    .compression = uWS::DISABLED,
    .maxPayloadLength = UserData::getInstance().msgSizeAllowedInBytes,
    .idleTimeout = UserData::getInstance().idleTimeoutInSeconds,
    .maxBackpressure = UserData::getInstance().maxBackpressureInBytes,
    .closeOnBackpressureLimit = false,
    .resetIdleTimeoutOnSend = true,
    .sendPingsAutomatically = true,
    .maxLifetime = UserData::getInstance().maxLifetimeInMinutes,

    /* Handlers */
    .upgrade = [](auto *res, auto *req, auto *context) {
        struct UpgradeData {
            std::string secWebSocketKey;
            std::string secWebSocketProtocol;
            std::string secWebSocketExtensions;
            std::string key;
            std::string uid;
            struct us_socket_context_t *context;
            decltype(res) httpRes;
            bool aborted = false;
        } *upgradeData = new UpgradeData {
            std::string(req->getHeader("sec-websocket-key")),
            std::string(req->getHeader("sec-websocket-protocol")),
            std::string(req->getHeader("sec-websocket-extensions")),
            std::string(req->getHeader("api-key")),
            std::string(req->getHeader("uid").data() ? req->getHeader("uid") : ""),
            context,
            res
        };

        res->onAborted([=]() {
            upgradeData->aborted = true;
        });

        if(upgradeData->uid.empty() || upgradeData->uid.length() > 4096) {
            totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

            res->cork([res]() {
                res->writeStatus("400 Bad Request");
                res->writeHeader("Content-Type", "application/json");
                res->end("INVALID_UID");
            });
        }

        if(isMultiThread) {
            /** Check if the user is banned and reject the connection */
            tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor bannedAccessor;
            if (ThreadSafe::bannedConnections.find(bannedAccessor, "global")) {
                /** Access the inner map */
                tbb::concurrent_hash_map<std::string, bool>& inner_map = bannedAccessor->second;

                /** Accessor for the inner map */
                tbb::concurrent_hash_map<std::string, bool>::accessor innerAccessor;
                
                /** Check if the user UID is banned in the inner map */
                if (inner_map.find(innerAccessor, upgradeData->uid)) {

                    totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("403 Forbidden");
                        res->writeHeader("Content-Type", "application/json");
                        res->end("CONNECTION_BANNED");
                    });

                    return;
                }
            }
        } else {
            /** Check if the user is banned and reject the connection */
            if (SingleThreaded::bannedConnections.find("global") != SingleThreaded::bannedConnections.end() 
            && SingleThreaded::bannedConnections["global"].find(upgradeData->uid) != SingleThreaded::bannedConnections["global"].end()) {
                
                totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);
                
                res->cork([res]() {
                    res->writeStatus("403 Forbidden");
                    res->writeHeader("Content-Type", "application/json");
                    res->end("CONNECTION_BANNED");
                });

                return;
            }
        }

        if(isMultiThread) {
            /** check if a connection is already there with the same uid (thread safe) */
            tbb::concurrent_hash_map<std::string, bool>::const_accessor accessor;
            if(ThreadSafe::uid.find(accessor, upgradeData->uid)){

                totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("409 Conflict")->end("UID_ALREADY_EXIST");
                });

                return;
            }
        } else {
            /** check if a connection is already there with the same uid (thread safe) */
            if(SingleThreaded::uid.find(upgradeData->uid) != SingleThreaded::uid.end()) {
                
                totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("409 Conflict")->end("UID_ALREADY_EXIST");
                });

                return;
            }
        }

        /** Check if the connection limit has been exceeded */
        if (globalConnectionCounter.load(std::memory_order_relaxed) >= UserData::getInstance().connections) {
            totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

            res->cork([res]() {
                res->writeStatus("503 Service Unavailable")->end("MAX_CONNECTION_LIMIT_REACHED");
            });

            return;
        }

        /** Check if API key is valid or not */
        if(UserData::getInstance().clientApiKey != upgradeData->key){
            totalConnectionErrors.fetch_add(1, std::memory_order_relaxed);

            res->cork([res]() {
                res->writeStatus("401 Unauthorized")->end("INVALID_API_KEY");
            });

            return;
        }

        if (!upgradeData->aborted) {
            upgradeData->httpRes->cork([upgradeData]() {
                upgradeData->httpRes->template upgrade<PerSocketData>({
                    /* We initialize PerSocketData struct here */
                    .key = upgradeData->key,
                    .uid = upgradeData->uid,
                }, upgradeData->secWebSocketKey,
                    upgradeData->secWebSocketProtocol,
                    upgradeData->secWebSocketExtensions,
                    upgradeData->context
                );
            });
        } 
    },
    .open = [this](auto *ws) {
        WebSocketData data;
        data.ws = ws;
        data.worker = this;

        std::string userId = ws->getUserData()->uid;

        /** Increment global connection counter */
        globalConnectionCounter.fetch_add(1, std::memory_order_relaxed);

        if(isMultiThread) {
            /** Thread-safe insertion into connections map */
            tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
            bool inserted = ThreadSafe::connections.insert(conn_accessor, userId);
            if (inserted) {
                conn_accessor->second = std::move(data);
            } else {
                /** UID already exists, something went wrong */
                ws->end();
                return;
            }
        } else {
            /** Single-threaded insertion into connections map */
            SingleThreaded::connections.emplace(userId, std::move(data));
        }

        if(isMultiThread) {
            /** Thread-safe insertion into uid map */
            tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;
            if (ThreadSafe::uid.insert(user_accessor, userId)) {
                user_accessor->second = true;
            } else {
                /** UID already exists, something went wrong */
                ws->end();
                return;
            }
        } else {
            /** Single-threaded insertion into uid map */
            SingleThreaded::uid.emplace(userId, true);
        }

        /** Subscribe to channels */
        ws->subscribe(userId);
        ws->subscribe(BROADCAST);
    },
    .message = [this](auto *ws, std::string_view message, uWS::OpCode opCode) {
        auto& userData = *ws->getUserData();
        auto uid = userData.uid;

        /** checking if the message sending is disabled globally at the server level */
        if(isMessagingDisabled.load(std::memory_order_relaxed)) {
            ws->send("{\"data\":\"MESSAGING_DISABLED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
            return;
        }

        /** checking if the messaging is disabled for a particular connection at global level */
        if(isMultiThread) {
            /** Check if messaging is disabled for the user */
            tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor outer_accessor;
            tbb::concurrent_hash_map<std::string, bool>::const_accessor inner_accessor;

            if (ThreadSafe::disabledConnections.find(outer_accessor, "global") &&
                outer_accessor->second.find(inner_accessor, uid)) {
                
                ws->send("{\"data\":\"MESSAGING_DISABLED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);

                return;
            }
        } else {
            /** Check if messaging is disabled for the user */
            auto globalIt = SingleThreaded::disabledConnections.find("global");

            if (globalIt != SingleThreaded::disabledConnections.end() && 
                globalIt->second.find(uid) != globalIt->second.end()) {

                /** Send a message to the user indicating messaging is disabled */
                ws->send(std::string_view{"{\"data\":\"MESSAGING_DISABLED\",\"source\":\"server\"}"}, uWS::OpCode::TEXT, true);

                return;
            }
        }

        if (ws->getUserData()->sendingAllowed)
        {
            if(ws->getBufferedAmount() > UserData::getInstance().maxBackpressureInBytes) {
                ws->send("{\"data\":\"YOU_ARE_RATE_LIMITED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                droppedMessages.fetch_add(1, std::memory_order_relaxed);
                ws->getUserData()->sendingAllowed = false;
            } else {
                try {
                    /** Parsing the message */
                    simdjson::padded_string jsonMessage(message.data(), message.size());
                    simdjson::ondemand::parser parser;
                    simdjson::ondemand::document parsedData;

                    /** Parse JSON and handle potential errors */
                    if (auto error = parser.iterate(jsonMessage).get(parsedData); error) {
                        ws->send(R"({"data":"INVALID_JSON","source":"server"})", uWS::OpCode::TEXT, true);
                        return;
                    }

                    /** Retrieve 'rid' */
                    std::string rid;
                    if (auto ridField = parsedData["rid"]; ridField.error() == simdjson::SUCCESS) {
                        rid = std::string(ridField.get_string().value());  
                    } else {
                        ws->send(R"({"data":"INVALID_JSON","source":"server"})", uWS::OpCode::TEXT, true);
                        return;
                    }

                    /** Retrieve 'message' */
                    std::string message;
                    if (auto msgField = parsedData["message"]; msgField.error() == simdjson::SUCCESS) {
                        message = std::string(msgField.get_string().value());  
                    } else {
                        ws->send(R"({"data":"INVALID_JSON","source":"server"})", uWS::OpCode::TEXT, true);
                        return;
                    }

                    uint8_t roomType = 255;

                    if(isMultiThread) {
                        /** Acquire an accessor for the outer map (UID to Room Mapping) */
                        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::const_accessor uid_to_rid_outer_accessor;
                    
                        /** Check if the user (UID) exists in the mapping */
                        if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, uid)) {
                            auto& inner_map = uid_to_rid_outer_accessor->second;
                    
                            /** Check if the room (RID) exists under the given UID */
                            tbb::concurrent_hash_map<std::string, uint8_t>::const_accessor uid_to_rid_inner_accessor;
                            
                            if (!inner_map.find(uid_to_rid_inner_accessor, rid)) {
                                /** Room not found under this UID, send response and return */
                                ws->send(R"({"data":"NO_SUBSCRIPTION_FOUND","source":"server"})", uWS::OpCode::TEXT, true);
                                return;
                            }
                    
                            /** Room exists, retrieve the room type */
                            roomType = uid_to_rid_inner_accessor->second;
                        } else {
                            /** No subscription found for the given UID, send response */
                            ws->send(R"({"data":"NO_SUBSCRIPTION_FOUND","source":"server"})", uWS::OpCode::TEXT, true);
                            return;
                        }
                    } else {
                        /** 
                         * Attempt to find the user (UID) in the room mapping.
                         * The map stores room associations for each user.
                         */
                        if (auto uidIt = SingleThreaded::uidToRoomMapping.find(uid); uidIt != SingleThreaded::uidToRoomMapping.end()) {
                            /** Get reference to the inner map containing room associations for this UID */
                            auto& roomMap = uidIt->second;

                            /** Attempt to find the given room (RID) */
                            if (auto ridIt = roomMap.find(rid); ridIt != roomMap.end()) {
                                /** Room exists, retrieve the room type */
                                roomType = ridIt->second;
                            } else {
                                /** Room not found under this UID, send error response */
                                ws->send(R"({"data":"NO_SUBSCRIPTION_FOUND","source":"server"})", uWS::OpCode::TEXT, true);
                                return;
                            }
                        } else {
                            /** No subscription found for the given UID, send error response */
                            ws->send(R"({"data":"NO_SUBSCRIPTION_FOUND","source":"server"})", uWS::OpCode::TEXT, true);
                            return;
                        }
                    }                     

                    if(isMultiThread) {
                        /** Check if messaging is disabled for the user */
                        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor outer_accessor;
                        tbb::concurrent_hash_map<std::string, bool>::const_accessor inner_accessor;

                        if((ThreadSafe::disabledConnections.find(outer_accessor, rid) &&
                            outer_accessor->second.find(inner_accessor, uid))) {
                            ws->send("{\"data\":\"MESSAGING_DISABLED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                            return;
                        } 
                    } else {
                        /** 
                         * Check if messaging is disabled for the user.
                         * The outer map stores disabled rooms (RID), and the inner set stores users (UIDs) who are blocked.
                         */
                        auto ridIt = SingleThreaded::disabledConnections.find(rid);

                        /** If the room exists in the disabledConnections map */
                        if (ridIt != SingleThreaded::disabledConnections.end() && 
                            ridIt->second.find(uid) != ridIt->second.end()) {
                            /** Messaging is disabled, send error response */
                            ws->send("{\"data\":\"MESSAGING_DISABLED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                            return;
                        }
                    }

                    /** publishing message */
                    std::string data = "{\"data\":\"" + message + "\",\"source\":\"user\",\"rid\":\"" + rid + "\"}";
                    ws->publish(rid, data, opCode, true);

                    std::for_each(::workers.begin(), ::workers.end(), [data, opCode, rid](worker_t &w) {
                        /** Check if the current thread ID matches the worker's thread ID */ 
                        if (std::this_thread::get_id() != w.thread_->get_id()) {
                            /** Defer the message publishing to the worker's loop */ 
                            w.loop_->defer([&w, data, opCode, rid]() {
                                w.app_->publish(rid, data, opCode, true);
                            });
                        }
                    });

                    unsigned int subscribers = app_->numSubscribers(rid);
                    globalMessagesSent.fetch_add(static_cast<unsigned long long>(subscribers), std::memory_order_relaxed);
                    totalPayloadSent.fetch_add(static_cast<unsigned long long>(data.size()) * static_cast<unsigned long long>(subscribers), std::memory_order_relaxed);   

                    /** Writing data to the LMDB */
                    if (roomType == static_cast<uint8_t>(Rooms::PUBLIC_CACHE)
                    || roomType == static_cast<uint8_t>(Rooms::PRIVATE_CACHE) 
                    || roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) 
                    || roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)
                    ) {
                        /** write the data in the local storage */
                        /* write_worker(rid, std::string(message)); */

                        /** update the LMDB write count */
                        totalLMDBWrites.fetch_add(1, std::memory_order_relaxed);

                        /** SQL integration works in cache channels only */
                        if(getFeatureStatus(Features::ENABLE_MYSQL_INTEGRATION) == 1){
                            db_handler->insertSingleData(getCurrentSQLTime(), std::string(message), uid, rid);
                        }
                    }

                    if(getWebhookStatus(Webhooks::ON_MESSAGE) == 1) {
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_MESSAGE\", "
                                << "\"uid\":\"" << uid << "\", "
                                << "\"rid\":\"" << rid << "\", "
                                << "\"message\":\"" << message << "\"}"; 

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                } catch (const simdjson::simdjson_error &e) {
                    ws->send("{\"data\":\"INVALID_JSON\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
                }
            }
        } else {
            ws->send("{\"data\":\"YOU_ARE_RATE_LIMITED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
            droppedMessages.fetch_add(1, std::memory_order_relaxed);
        }    
    },
    .dropped = [](auto *ws, std::string_view message, uWS::OpCode /*opCode*/) {
        droppedMessages.fetch_add(1, std::memory_order_relaxed);
        ws->send("{\"data\":\"MESSAGE_DROPPED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
    },
    .drain = [](auto *ws) {
        if(ws->getBufferedAmount() < (UserData::getInstance().maxBackpressureInBytes / 2)){
            ws->getUserData()->sendingAllowed = true;
            ws->send("{\"data\":\"RATE_LIMIT_LIFTED\",\"source\":\"server\"}", uWS::OpCode::TEXT, true);
        }
    },
    .ping = [](auto *ws, std::string_view) {
        /** automatically handled */
    },
    .pong = [](auto *ws, std::string_view) {
        /** automatically handled */
    },
    .close = [this](auto *ws, int /* code */, std::string_view /* message */) {
        std::string userId = ws->getUserData()->uid;

        /** Decrement global connection counter */
        globalConnectionCounter.fetch_sub(1, std::memory_order_relaxed);

        /** Thread-safe removal from connections map */
        if(isMultiThread) {
            tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
            if (ThreadSafe::connections.find(conn_accessor, userId)) {
                ThreadSafe::connections.erase(conn_accessor);  
            }
        } else {
            SingleThreaded::connections.erase(userId);
        }

        /** Thread-safe removal from uid map */
        if(isMultiThread) {
            tbb::concurrent_hash_map<std::string, bool>::accessor uid_accessor;
            if (ThreadSafe::uid.find(uid_accessor, userId)) {
                ThreadSafe::uid.erase(uid_accessor);  
            }
        } else {
            SingleThreaded::uid.erase(userId);
        }

        /** Manually unsubscribing */
        ws->unsubscribe(userId);
        ws->unsubscribe(BROADCAST);

        /** fetching all the RID for the UID and removing the UID from the map */
        if (isMultiThread) {
            /** Acquire access to the outer concurrent map */
            tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor outer_accessor;
        
            /** Check if the user ID exists in the map */
            if (ThreadSafe::uidToRoomMapping.find(outer_accessor, userId)) {
                /** Reference to the inner map (rooms associated with the user ID) */
                auto& inner_map = outer_accessor->second;
                
                /** Iterate through the inner map and move data into `rids` */
                for (auto& entry : inner_map) {
                    /** Close connection */
                    closeConnection(ws, this, entry.first, userId, entry.second, true);
                }
        
                /** Remove the user ID entry from the outer map */
                ThreadSafe::uidToRoomMapping.erase(outer_accessor);
            }
        } else {
            /** Check if the user ID exists in the map */
            auto it = SingleThreaded::uidToRoomMapping.find(userId);
            if (it != SingleThreaded::uidToRoomMapping.end()) {
                /** Move the inner set directly */
                auto& inner_set = it->second;

                /** Move each element from the set to `rids` using a loop */
                for (auto& entry : inner_set) {
                    closeConnection(ws, this, entry.first, userId, entry.second, true);
                }

                /** Erase the user ID entry from the outer map */
                SingleThreaded::uidToRoomMapping.erase(it);
            }
        }        
    }
    }).get("/api/v1/metrics", [](auto *res, auto *req) {
        /** fetch all the server metrics */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            if (req->getHeader("api-key") != UserData::getInstance().adminApiKey) {
    
                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("401 Unauthorized");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access. Invalid API key!"})");
                    });
                }
    
                return;
            }
    
            if (!*isAborted) {
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                res->writeStatus("200 OK");
                res->writeHeader("Content-Type", "application/json");
                res->end(R"({"connections": )" 
                    + std::to_string(globalConnectionCounter.load(std::memory_order_relaxed)) 
                    + R"(,"messages_sent": )" 
                    + std::to_string(globalMessagesSent.load(std::memory_order_relaxed))
                    + R"(,"total_payload_sent": )" 
                    + std::to_string(totalPayloadSent.load(std::memory_order_relaxed)) 
                    + R"(,"total_failed_api_calls": )" 
                    + std::to_string(totalFailedApiCalls.load(std::memory_order_relaxed))
                    + R"(,"total_success_api_calls": )" 
                    + std::to_string(totalSuccessApiCalls.load(std::memory_order_relaxed))
                    + R"(,"total_failed_connection_attempts": )" 
                    + std::to_string(totalConnectionErrors.load(std::memory_order_relaxed))
                    + R"(,"total_mysql_db_batch_writes": )" 
                    + std::to_string(totalMysqlDBWrites.load(std::memory_order_relaxed))
                    + R"(,"total_local_db_writes": )" 
                    + std::to_string(totalLMDBWrites.load(std::memory_order_relaxed))
                    + R"(,"total_success_webhook_calls": )" 
                    + std::to_string(totalSuccessWebhookCalls.load(std::memory_order_relaxed))
                    + R"(,"total_failed_webhook_calls": )" 
                    + std::to_string(totalFailedWebhookCalls.load(std::memory_order_relaxed))
                    + R"(,"average_latency": )" 
                    + std::to_string(localEma) 
                    + R"(,"dropped_messages": )" 
                    + std::to_string(droppedMessages.load(std::memory_order_relaxed)) 
                    + R"(})");
                });
            }            
        } catch (std::exception &e) {
            if (!*isAborted) {
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).post("/api/v1/invalidate", [](auto *res, auto *req) {
        /** update the metadata used by the server */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");
            std::string_view secret = req->getHeader("secret");

            /** check if the API key is valid or not */
            if(apiKey != UserData::getInstance().adminApiKey){

                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("400 Unauthorized");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                    });
                }

                return;
            }

            std::string body;
        
            body.reserve(1024);

            res->onData([res, req, body = std::move(body), secret, isAborted](std::string_view data, bool last) mutable {
                body.append(data.data(), data.length());

                if (last) { 
                    try {
                        /** generate the secret and compare */
                        unsigned char hmac_result[HMAC_SHA256_DIGEST_LENGTH];  /**< Buffer to store the HMAC result */
                        hmac_sha256(SECRET, strlen(SECRET), body.c_str(), body.length(), hmac_result);  /**< Compute HMAC */

                        /** compare HMAC and respond accordingly */
                        if(secret != to_hex(hmac_result, HMAC_SHA256_DIGEST_LENGTH)){

                            if(!*isAborted){
                                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                                res->cork([res]() {
                                    res->writeStatus("400 Unauthorized");
                                    res->writeHeader("Content-Type", "application/json");
                                    res->end(R"({"message": "Unauthorized access, Invalid signature!"})");
                                });
                            }

                            return;
                        }

                        /** Parse the JSON response */ 
                        int action = populateUserData(body);
                        
                        if(action == 1){
                            /** check if the connection parameters are changed */
                            std::for_each(::workers.begin(), ::workers.end(), [](worker_t &w) {
                                /** Defer the message publishing to the worker's loop */ 
                                w.loop_->defer([&w]() {
                                    w.db_handler->manualCreateConnection();
                                });
                            });
                        } else if(action == -1) {
                            std::for_each(::workers.begin(), ::workers.end(), [](worker_t &w) {
                                /** Defer the message publishing to the worker's loop */ 
                                w.loop_->defer([&w]() {
                                    w.db_handler->flushRemainingData();
                                    w.db_handler->disconnect();
                                });
                            });
                        }

                        if(!*isAborted){
                            totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("200 OK");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Metadata invalidated successfully!"})");
                            });
                        }

                        if(action == 2){
                            std::thread([]() {
                                std::this_thread::sleep_for(std::chrono::seconds(1)); 
                                std::exit(0);
                            }).detach();
                        }
                    } catch (std::exception &e) {
                        if(!*isAborted){
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
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/mysql/sync", [](auto *res, auto *req) {
        /** sync all the data in the buffers to integrated mysql server */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
    
                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("401 Unauthorized");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access. Invalid API key!"})");
                    });
                }
    
                return;
            }

            if(getFeatureStatus(Features::ENABLE_MYSQL_INTEGRATION) == 0){
                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("403 Forbidden");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "MySQL integration is disabled!"})");
                    });
                }
    
                return;
            }
    
            std::for_each(::workers.begin(), ::workers.end(), [](worker_t &w) {
                /** Defer the message publishing to the worker's loop */ 
                w.loop_->defer([&w]() {
                    w.db_handler->flushRemainingData();
                });
            });
    
            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "MySQL data synced successfully!"})");
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/rooms/users/all", [this](auto *res, auto *req) {
        /** fetch all the rooms present on the server */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
    
                if(!*isAborted){
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
            
            if(isMultiThread) {
                for (const auto& [rid, users] : ThreadSafe::topics) {  
                    /** Create a JSON object for the room */
                    nlohmann::json roomData;
                    roomData["rid"] = rid;
        
                    /** Store only the keys from the inner map */
                    std::vector<std::string> userKeys;
                    
                    for (const auto& [uid, _] : users) {  
                        userKeys.push_back(uid);
                    }
        
                    /** Convert vector to JSON array */
                    roomData["uid"] = std::move(userKeys);
        
                    /** Store the room data in the final list */
                    data.push_back(std::move(roomData));
                }
            } else {
                for (const auto& [rid, users] : SingleThreaded::topics) {  
                    /** Create a JSON object for the room */
                    data.push_back({
                        {"rid", rid},
                        {"uid", nlohmann::json(users)}  
                    });
                }                
            }
            
            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res, data]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(data.dump());  
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/users/orphan", [this](auto *res, auto *req) {
        /** fetch all the rooms present on the server */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
    
                if(!*isAborted){
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

            if(isMultiThread) {
                for (auto it = ThreadSafe::uid.begin(); it != ThreadSafe::uid.end(); ++it) {
                    if (it->second) {  
                        orphanUids.push_back(it->first);
                    }
                }
            } else {
                for (const auto& [uid, isOrphan] : SingleThreaded::uid) {  
                    if (isOrphan) {  
                        orphanUids.emplace_back(uid);
                    }
                }
            }
            
            nlohmann::json data;
            data["uid"] = orphanUids;
            
            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res, data]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(data.dump());  
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).post("/api/v1/rooms/users", [this](auto *res, auto *req) {
        /** get all the connectiond for a room */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");

            if(apiKey != UserData::getInstance().adminApiKey){

                if(!*isAborted){
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

            res->onData([res, req, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
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

                            if(isMultiThread) {
                                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor outer_accessor;

                                if (ThreadSafe::topics.find(outer_accessor, rid)) {
                                    /** Convert the inner map to a JSON array */
                                    nlohmann::json uidArray = nlohmann::json::array();
                                    
                                    /** Iterate over the inner map and add the uids to the JSON array */
                                    for (const auto& entry : outer_accessor->second) {
                                        uidArray.push_back(entry.first);  /** entry.first is the uid */ 
                                    }
                                    
                                    roomData["uid"] = uidArray;
                                } else {
                                    roomData["uid"] = nlohmann::json::array(); /** Empty array for missing `rid` */
                                }
                            } else {
                                auto it = SingleThreaded::topics.find(rid);
                                if (it != SingleThreaded::topics.end()) {
                                    roomData["uid"] = nlohmann::json(it->second);
                                } else {
                                    roomData["uid"] = nlohmann::json::array(); /** Empty array for missing `rid` */
                                }
                            }
                            
                            data.push_back(roomData);
                        }

                        if(!*isAborted){
                            totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res, data]() {
                                res->writeStatus("200 OK");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(data.dump()); 
                            });
                        }
                    } catch (std::exception &e) {
                        if(!*isAborted){
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
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/users/subscribe/room/:rid", [this](auto *res, auto *req) {
        std::atomic<bool> isAborted = false;
        std::string rid = std::string(req->getParameter("rid"));  /** Extract the room ID from the request */
        std::string uid = std::string(req->getHeader("uid"));  /** Extract the user ID from the request */

        res->onAborted([&isAborted]() { 
            isAborted.store(true); 
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            if (req->getHeader("api-key") != UserData::getInstance().clientApiKey) {
                if(!isAborted.load()){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("401 Unauthorized");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                    });
                }

                return;
            }
    
            uWS::WebSocket<true, true, PerSocketData>* ws = nullptr;
            worker_t* worker = nullptr;
            
            if(isMultiThread) {
                /** Checking if a connection exists for the provided UID */
                tbb::concurrent_hash_map<std::string, WebSocketData>::const_accessor accessor;

                /** Attempt to find the connection */
                if (!ThreadSafe::connections.find(accessor, uid)) {

                    /** Ensure the response is sent only once */
                    if(!isAborted.load()){
                        /** Atomically increment the rejected request counter */
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        /** Batch write operations for improved performance */
                        res->cork([res]() {
                            res->writeStatus("404 Not Found");  /** Set HTTP status */
                            res->writeHeader("Content-Type", "application/json");  /** Define response type */
                            res->end(R"({"message": "Invalid uid!"})");  /** Send error message */
                        });
                    }

                    return;  /** Exit early since the UID is invalid */
                }

                /** Retrieve the connection object */
                ws = accessor->second.ws;
                worker = accessor->second.worker;
            } else {
                if (SingleThreaded::connections.find(uid) == SingleThreaded::connections.end()) {
                    if(!isAborted.load()){
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("404 Not Found");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Invalid uid!"})");
                        });
                    }
                    return;
                }

                ws = SingleThreaded::connections[uid].ws;
                worker = SingleThreaded::connections[uid].worker;
            }

            /** Validate the room ID (rid) length constraints */
            if (rid.empty() || rid.size() > 160) {
                /** Ensure the response is sent only once */
                if(!isAborted.load()){
                    /** Atomically increment the rejected request counter */
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    /** Batch response writes for efficiency */
                    res->cork([res]() {
                        res->writeStatus("400 Bad Request");  /** Set HTTP status */
                        res->writeHeader("Content-Type", "application/json");  /** Define response type */
                        res->end(R"({"message": "The room ID length should be between 1 to 160 characters!"})");  /** Send error message */
                    });
                }

                return;  /** Exit early since rid is invalid */
            }

            uint8_t roomType = 255;

            /** checking if the correct room type is received */
            if (rid.rfind("pub-state-cache-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE);
            }
            else if (rid.rfind("pri-state-cache-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE);
            }
            else if (rid.rfind("pub-cache-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PUBLIC_CACHE);
            }
            else if (rid.rfind("pri-cache-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PRIVATE_CACHE);
            }
            else if (rid.rfind("pub-state-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PUBLIC_STATE);
            }
            else if (rid.rfind("pri-state-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PRIVATE_STATE);
            }
            else if (rid.rfind("pub-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PUBLIC);
            }
            else if (rid.rfind("pri-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PRIVATE);
            }
            else
            {                        
                if(!isAborted.load()){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("400 Bad Request");
                        res->writeHeader("Content-Type", "application/json");
                        res->end("{\"message\": \"The provided room type is invalid!\"}");
                    });
                }

                return;
            }

            if(isMultiThread) {
                /** checking if the user is already subscribed to the given room */
                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::const_accessor uid_to_rid_outer_accessor;

                /** Check if the UID is present in the mapping */
                if (ThreadSafe::uidToRoomMapping.find(uid_to_rid_outer_accessor, uid)) {
                    /** Retrieve reference to the inner map containing room IDs */
                    auto& inner_map = uid_to_rid_outer_accessor->second;

                    /** Check if the room is already associated with the UID */
                    tbb::concurrent_hash_map<std::string, uint8_t>::const_accessor inner_accessor;
                    if (inner_map.find(inner_accessor, rid)) {
                        

                        /** Ensure response is not sent multiple times */
                        if(!isAborted.load()){
                            /** Increment rejected request counter in a relaxed memory order for efficiency */
                            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                            /** Use `cork` to optimize response writing */
                            res->cork([res]() {
                                res->writeStatus("400 Bad Request"); /** Set HTTP status */
                                res->writeHeader("Content-Type", "application/json"); /** Set response type */
                                res->end(R"({"message": "You are already subscribed to the given room!"})"); /** Send error message */
                            });
                        }

                        return; /** Exit early since user is already subscribed */
                    }
                }
            } else {
                auto it = SingleThreaded::uidToRoomMapping.find(uid);
                if (it != SingleThreaded::uidToRoomMapping.end() && it->second.find(rid) != it->second.end()) {

                    if(!isAborted.load()){
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
            
            /** checking if the user is banned from the given room */
            if(isMultiThread) {
                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor outer_accessor;
                
                if (ThreadSafe::bannedConnections.find(outer_accessor, rid) && outer_accessor->second.count(uid)) {

                    if(!isAborted.load()){
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("403 Forbidden");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "You have been banned from this room!"})");
                        });
                    }
                    
                    return;
                }
            } else {
                auto it = SingleThreaded::bannedConnections.find(rid);
                if (it != SingleThreaded::bannedConnections.end() && it->second.count(uid)) {

                    if(!isAborted.load()){
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

            if(roomType == static_cast<uint8_t>(Rooms::PRIVATE) 
            || roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE) 
            || roomType == static_cast<uint8_t>(Rooms::PRIVATE_CACHE) 
            || roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)
            ){
                if(getWebhookStatus(Webhooks::ON_VERIFICATION_REQUEST) == 1){
                    std::ostringstream payload;

                    payload << "{\"event\":\"ON_VERIFICATION_REQUEST\", "
                    << "\"uid\":\"" << uid << "\", "
                    << "\"rid\":\"" << rid << "\"}";

                    std::string body = payload.str(); 
                    httplib::Headers headers = {};

                    /** if the webhook secret is present add the hmac */
                    if(UserData::getInstance().webhookSecret.length() > 0){
                        unsigned char hmac_result[HMAC_SHA256_DIGEST_LENGTH];  /**< Buffer to store the HMAC result */
                        hmac_sha256(SECRET, strlen(SECRET), body.c_str(), body.length(), hmac_result);  /**< Compute HMAC */
                        headers = {{"X-HMAC-Signature", to_hex(hmac_result, HMAC_SHA256_DIGEST_LENGTH)}}; 
                    }

                    int status = sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {},
                        true
                    );

                    if(status != 200){                                
                        if(!isAborted.load()){
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
                    if(!isAborted.load()){
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("403 Forbidden");
                            res->writeHeader("Content-Type", "application/json");
                            res->end("{\"message\": \"The ON_VERIFICATION_REQUEST webhook must be enabled to activate private rooms!\"}");
                        });
                    }

                    return;
                } 
            }

            openConnection(ws, worker, rid, roomType);

            if(!isAborted.load()){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Successfully subscribed to the given room!"})");
                });
            }
        } catch (std::exception &e) {
            if(!isAborted.load()){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/users/subscriptions/all", [this](auto *res, auto *req) {
        /** get all the subscribed rooms from the given UIDs */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");

            if(apiKey != UserData::getInstance().adminApiKey){

                if(!*isAborted){
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
            
            if(isMultiThread) {
                for (const auto& [uid, rids] : ThreadSafe::uidToRoomMapping) {  
                    /** Create a JSON object for the room */
                    nlohmann::json roomData;
                    roomData["uid"] = uid;
        
                    /** Store only the keys from the inner map */
                    std::vector<std::string> roomIDs;
                    
                    for (const auto& [uid, _] : rids) {  
                        roomIDs.push_back(uid);
                    }
        
                    /** Convert vector to JSON array */
                    roomData["rid"] = std::move(roomIDs);
        
                    /** Store the room data in the final list */
                    data.push_back(std::move(roomData));
                }
            } else {
                /** 
                 * Iterate through each user (UID) in the mapping.
                 * The outer map contains a mapping from UID to a set of rooms.
                 */
                for (const auto& [uid, rids] : SingleThreaded::uidToRoomMapping) {  
                    /** Create a JSON object for the room */
                    nlohmann::json roomData;
                    roomData["uid"] = uid;

                    /** Use a more efficient constructor to extract keys from the inner map */
                    std::vector<std::string> roomIDs;
                    roomIDs.reserve(rids.size());  // Reserve space to avoid multiple reallocations

                    std::transform(rids.begin(), rids.end(), std::back_inserter(roomIDs), [](const auto& pair) { return pair.first; });

                    /** Store extracted room IDs in JSON */
                    roomData["rid"] = std::move(roomIDs);

                    /** Store the room data in the final list */
                    data.push_back(std::move(roomData));
                }
            }

            std::string response = data.dump();

            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res, response]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(response); 
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).post("/api/v1/users/subscriptions", [this](auto *res, auto *req) {
        /** get all the subscribed rooms from the given UIDs */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");

            if(apiKey != UserData::getInstance().adminApiKey){
                if(!*isAborted){
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

            res->onData([res, req, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
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

                            if(isMultiThread) {
                                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::accessor outer_accessor;

                                if (ThreadSafe::uidToRoomMapping.find(outer_accessor, uid)) {
                                    /** Convert the inner map to a JSON array */
                                    nlohmann::json ridArray = nlohmann::json::array();
                                    
                                    /** Iterate over the inner map and add the uids to the JSON array */
                                    for (const auto& entry : outer_accessor->second) {
                                        ridArray.push_back(entry.first);  /** entry.first is the uid */ 
                                    }
                                    
                                    roomData["rid"] = ridArray;
                                } else {
                                    roomData["rid"] = nlohmann::json::array(); /** Empty array for missing `rid` */
                                }
                            } else {
                                /** 
                                 * Check if the user (UID) exists in the mapping.
                                 * If it exists, extract the associated room IDs (RIDs).
                                 */
                                if (auto uidIt = SingleThreaded::uidToRoomMapping.find(uid); uidIt != SingleThreaded::uidToRoomMapping.end()) {
                                    /** Reserve space to avoid multiple reallocations */
                                    nlohmann::json ridArray = nlohmann::json::array();
                                    ridArray.get_ptr<nlohmann::json::array_t*>()->reserve(uidIt->second.size());

                                    /** Use `transform` to efficiently populate the JSON array */
                                    std::transform(uidIt->second.begin(), uidIt->second.end(), std::back_inserter(ridArray), [](const auto& entry) { return entry.first; });

                                    roomData["rid"] = std::move(ridArray);
                                } else {
                                    /** Assign an empty array if no room IDs are found */
                                    roomData["rid"] = nlohmann::json::array();
                                }
                            }
                            
                            data.push_back(roomData);
                        }

                        if(!*isAborted){
                            totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res, data]() {
                                res->writeStatus("200 OK");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(data.dump()); 
                            });
                        }
                    } catch (std::exception &e) {
                        if(!*isAborted){
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
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/users/unsubscribe/room/:rid", [this](auto *res, auto *req) {
        auto isAborted = std::make_shared<bool>(false);
        std::string rid = std::string(req->getParameter("rid"));  /** Extract the room ID from the request */
        std::string uid = std::string(req->getHeader("uid"));  /** Extract the user ID from the request */

        res->onAborted([isAborted]() { 
            *isAborted = true; 
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            if (req->getHeader("api-key") != UserData::getInstance().clientApiKey) {
                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("401 Unauthorized");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                    });
                }

                return;
            }
    
            uWS::WebSocket<true, true, PerSocketData>* ws = nullptr;
            worker_t* worker = nullptr;

            if(isMultiThread) {
                /** checking if there even is a connection with the provided UID */
                tbb::concurrent_hash_map<std::string, WebSocketData>::const_accessor accessor;

                if (!ThreadSafe::connections.find(accessor, uid)) {
                    if(!*isAborted){
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
            } else {
                if (SingleThreaded::connections.find(uid) == SingleThreaded::connections.end()) {
                    if(!*isAborted){
                        totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                        res->cork([res]() {
                            res->writeStatus("404 Not Found");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Invalid uid!"})");
                        });
                    }
                    return;
                }

                ws = SingleThreaded::connections[uid].ws;
                worker = SingleThreaded::connections[uid].worker;
            }

            /** checking if the room length is valid */
            if (rid.empty() || rid.length() > 160) {
                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("400 Bad Request");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "The room id length should be between 1 to 160 characters!"})");
                    });
                }

                return;
            }

            uint8_t roomType = 255;

            /** checking if the correct room type is received */
            if (rid.rfind("pub-state-cache-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE);
            }
            else if (rid.rfind("pri-state-cache-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE);
            }
            else if (rid.rfind("pub-cache-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PUBLIC_CACHE);
            }
            else if (rid.rfind("pri-cache-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PRIVATE_CACHE);
            }
            else if (rid.rfind("pub-state-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PUBLIC_STATE);
            }
            else if (rid.rfind("pri-state-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PRIVATE_STATE);
            }
            else if (rid.rfind("pub-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PUBLIC);
            }
            else if (rid.rfind("pri-", 0) == 0)
            {
                roomType = static_cast<uint8_t>(Rooms::PRIVATE);
            }
            else
            {                        
                if(!*isAborted){
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
            if (isMultiThread) {
                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, uint8_t>>::const_accessor uid_to_rid_outer_accessor;
                
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
            } else {
                auto it = SingleThreaded::uidToRoomMapping.find(uid);
                if ((it != SingleThreaded::uidToRoomMapping.end() && it->second.find(rid) == it->second.end()) || (it == SingleThreaded::uidToRoomMapping.end())) {

                    if(!*isAborted){
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

            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Successfully unsubscribed from the given room!"})");
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).post("/api/v1/broadcast", [this](auto *res, auto *req) {
        /** broadcast a message to everyone connected to the server */
        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
    
                if(!*isAborted){
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
    
            res->onData([res, req, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
                body.append(data.data(), data.length());
    
                if (last) { 
                    try {
                        nlohmann::json parsedJson = nlohmann::json::parse(body);
    
                        std::string message = parsedJson["message"].get<std::string>();
                        std::string messageToBroadcast = "{\"data\":\"" + message + "\",\"source\":\"admin\",\"rid\":\"" + BROADCAST + "\"}";

                        /** broadcast a message to all the rooms */
                        std::for_each(::workers.begin(), ::workers.end(), [messageToBroadcast](worker_t &w) {
                            /** Defer the message publishing to the worker's loop */ 
                            w.loop_->defer([&w, messageToBroadcast]() {
                                w.app_->publish(BROADCAST, messageToBroadcast, uWS::OpCode::TEXT, true);
                            });
                        });
    
                        if(!*isAborted){
                            totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("200 OK");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Successfully broadcasted the message to everyone on the server!"})");
                            });
                        }
                    } catch (std::exception &e) {
                        if(!*isAborted){
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
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).post("/api/v1/rooms/broadcast", [this](auto *res, auto *req) {
        /** broadcast a message to a particular room */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");

            if(apiKey != UserData::getInstance().adminApiKey){

                if(!*isAborted){
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

            res->onData([res, req, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
                body.append(data.data(), data.length());

                if (last) { 
                    try {
                        nlohmann::json parsedJson = nlohmann::json::parse(body);

                        std::string message = parsedJson["message"].get<std::string>();
                        std::vector<std::string> rids = parsedJson["rid"].get<std::vector<std::string>>();

                        for (const auto& rid : rids) {
                            std::string messageToBroadcast = "{\"data\":\"" + message + "\",\"source\":\"admin\",\"rid\":\"" + rid + "\"}";

                            /** broadcast a message to a specific room */
                            std::for_each(::workers.begin(), ::workers.end(), [messageToBroadcast, rid](worker_t &w) {
                                /** Defer the message publishing to the worker's loop */ 
                                w.loop_->defer([&w, messageToBroadcast, rid]() {
                                    w.app_->publish(rid, messageToBroadcast, uWS::OpCode::TEXT, true);
                                });
                            });
                        }

                        if(!*isAborted){
                            totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("200 OK");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Successfully broadcasted the message to the given rooms!"})");
                            });
                        }
                    } catch (std::exception &e) {
                        if(!*isAborted){
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
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).post("/api/v1/users/broadcast", [this](auto *res, auto *req) {
        /** broadcast a message to a particular connection */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");

            if(apiKey != UserData::getInstance().adminApiKey){

                if(!*isAborted){
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

            res->onData([res, req, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
                body.append(data.data(), data.length());

                if (last) { 
                    try {
                        nlohmann::json parsedJson = nlohmann::json::parse(body);

                        std::string message = parsedJson["message"].get<std::string>();
                        std::vector<std::string> uids = parsedJson["uid"].get<std::vector<std::string>>();

                        for (const auto& uid : uids) {
                            std::string messageToBroadcast = "{\"data\":\"" + message + "\",\"source\":\"admin\",\"rid\":\"" + uid + "\"}";

                            /** broadcast a message to a specific member of a room */
                            std::for_each(::workers.begin(), ::workers.end(), [messageToBroadcast, uid](worker_t &w) {
                                /** Defer the message publishing to the worker's loop */ 
                                w.loop_->defer([&w, messageToBroadcast, uid]() {
                                    w.app_->publish(uid, messageToBroadcast, uWS::OpCode::TEXT, true);
                                });
                            });
                        }

                        if(!*isAborted){
                            totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("200 OK");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Successfully broadcasted the message to the given connections!"})");
                            });
                        }
                    } catch (std::exception &e) {
                        if(!*isAborted){
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
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).post("/api/v1/rooms/users/ban", [this](auto *res, auto *req) {
        /** ban all the users in a room and prevent them from connecting again (it will disconnect the user from the server) */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");

            if(apiKey != UserData::getInstance().adminApiKey){

                if(!*isAborted){
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

            res->onData([res, req, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
                body.append(data.data(), data.length());

                if (last) { 
                    try {
                        nlohmann::json parsedJson = nlohmann::json::parse(body);

                        /** saving all the banned connections in a map */
                        for (const auto& item : parsedJson) {
                            /** Extract `rid` and `uid` from each item in the request */ 
                            std::string rid = item["rid"];
                            std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();
                            
                            if(isMultiThread) {
                                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor global_accessor;
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
                                        tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
                                        if (ThreadSafe::connections.find(conn_accessor, uid)) {
                                            uWS::WebSocket<true, true, PerSocketData>* ws = conn_accessor->second.ws; 
                                            worker_t* worker = conn_accessor->second.worker; 

                                            /** Disconnect the WebSocket or perform any other disconnection logic */
                                            worker->loop_->defer([ws]() {
                                                ws->end(1008, "{\"data\":\"YOU_HAVE_BEEN_BANNED\", \"source\":\"admin\"}");
                                            });
                                        }
                                    }
                                }
                            } else {
                                /** Insert or update banned connections efficiently */
                                auto& bannedSet = SingleThreaded::bannedConnections[rid];

                                /** Insert all UIDs into the banned set in one operation */
                                bannedSet.insert(uids.begin(), uids.end());

                                /** Iterate over the list of UIDs and disconnect banned users */
                                for (const auto& uid : uids) {
                                    /** Check if the UID exists in active connections */
                                    if (auto it = SingleThreaded::connections.find(uid); it != SingleThreaded::connections.end()) {
                                        /** Defer execution to properly close the WebSocket connection */
                                        it->second.worker->loop_->defer([ws = it->second.ws]() {
                                            /** Send a WebSocket close message with a ban notification */
                                            ws->end(1008, R"({"data":"YOU_HAVE_BEEN_BANNED", "source":"admin"})");
                                        });
                                    }
                                }
                            }
                        }

                        if(!*isAborted){
                            totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("200 OK");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Given users are successfully banned from the given rooms!"})");
                            });
                        }
                    } catch (std::exception &e) {
                        if(!*isAborted){
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
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).post("/api/v1/rooms/users/unban", [this](auto *res, auto *req) {
        /** ban all the users in a room and prevent them from connecting again (it will disconnect the user from the server) */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");

            if(apiKey != UserData::getInstance().adminApiKey){

                if(!*isAborted){
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

            res->onData([res, req, body = std::move(body), isAborted](std::string_view data, bool last) mutable {
                body.append(data.data(), data.length());

                if (last) { 
                    try {
                        nlohmann::json parsedJson = nlohmann::json::parse(body);

                        for (const auto& item : parsedJson) {
                            /** Extract `rid` and `uid` from each item in the request */ 
                            std::string rid = item["rid"];
                            std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                            if(isMultiThread) {
                                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor global_accessor;
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
                            } else {
                                auto it = SingleThreaded::bannedConnections.find(rid);
                                if (it != SingleThreaded::bannedConnections.end()) {
                                    for (const auto& uid : uids) {
                                        it->second.erase(uid);
                                    }

                                    if (it->second.empty()) {
                                        SingleThreaded::bannedConnections.erase(it);
                                    }
                                }
                            }
                        }

                        if(!*isAborted){
                            totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res]() {
                                res->writeStatus("200 OK");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"message": "Given users are successfully unbanned from the given rooms!"})");
                            });
                        }
                    } catch (std::exception &e) {
                        if(!*isAborted){
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
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).put("/api/v1/server/messaging/:action", [this](auto *res, auto *req) {
        /** enable or disable message sending at the server level (for everyone) */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");
            std::string_view action = req->getParameter("action");

            if(apiKey != UserData::getInstance().adminApiKey){

                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("403");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                    });
                }

                return;
            }

            if (action == "enable")
            {
                isMessagingDisabled.store(false, std::memory_order_relaxed);
            }
            else if (action == "disable")
            {
                isMessagingDisabled.store(true, std::memory_order_relaxed);
            }
            else
            {
                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("400 Bad Request");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Invalid action!"})");
                    });
                }
                return;
            }

            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res, action]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");

                    if(action == "enable")
                        res->end(R"({"message": "Messaging successfully enabled for everyone!"})");
                    else
                        res->end(R"({"message": "Messaging successfully disabled for everyone!"})");
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).post("/api/v1/rooms/messaging/:action", [this](auto *res, auto *req) {
        /** enable or disable messaging at room level */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");
            std::string_view action = req->getParameter("action");

            if(apiKey != UserData::getInstance().adminApiKey){

                if(!*isAborted){
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

            res->onData([res, req, body = std::move(body), action, isAborted](std::string_view data, bool last) mutable {
                body.append(data.data(), data.length());

                if (last) { 
                    try {
                        nlohmann::json parsedJson = nlohmann::json::parse(body);

                        for (const auto& item : parsedJson) {
                            /** Extract `rid` and `uid` from each item in the request */ 
                            std::string rid = item["rid"];
                            std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                            if (action == "enable")
                            {
                                if(isMultiThread) {
                                    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor global_accessor;
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
                                } else {
                                    if (auto it = SingleThreaded::disabledConnections.find(rid); it != SingleThreaded::disabledConnections.end()) {
                                        for (const auto& uid : uids) {
                                            it->second.erase(uid);
                                        }
                                    
                                        if (it->second.empty()) {
                                            SingleThreaded::disabledConnections.erase(it);
                                        }
                                    }                                    
                                }
                            }
                            else if (action == "disable")
                            {
                                if(isMultiThread) {
                                    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor global_accessor;
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
                                } else {
                                    for (const auto& uid : uids) {
                                        SingleThreaded::disabledConnections[rid].insert(uid);
                                    }
                                }
                            }
                            else
                            {
                                if(!*isAborted){
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

                        if(!*isAborted){
                            totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                            res->cork([res, action]() {
                                res->writeStatus("200 OK");
                                res->writeHeader("Content-Type", "application/json");

                                if(action == "enable")
                                    res->end(R"({"message": "Messaging successfully enabled for the given members in the given rooms!"})");
                                else
                                    res->end(R"({"message": "Messaging successfully disabled for the given members in the given rooms!"})");
                            });
                        }
                    } catch (std::exception &e) {
                        if(!*isAborted){
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
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/users/banned", [this](auto *res, auto *req) {
        /** Handle the request to fetch all banned connections */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");

            /** Check if the API key is valid */
            if (apiKey != UserData::getInstance().adminApiKey) {

                /** Respond with 403 Unauthorized if the API key is invalid */
                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("403");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                    });
                }

                return;
            }

            /** Create and reserve space for the JSON response */
            nlohmann::json data = nlohmann::json::array(); 

            if(isMultiThread) {
                for (const auto& [rid, users] : ThreadSafe::bannedConnections) {  
                    /** Create a JSON object for the room */
                    nlohmann::json roomData;
                    roomData["rid"] = rid;
    
                    /** Store only the keys from the inner map */
                    std::vector<std::string> userKeys;
                    
                    for (const auto& [uid, _] : users) {  
                        userKeys.push_back(uid);
                    }
    
                    /** Convert vector to JSON array */
                    roomData["uid"] = std::move(userKeys);
    
                    /** Store the room data in the final list */
                    data.push_back(std::move(roomData));
                }
            } else {
                for (const auto& [rid, users] : SingleThreaded::bannedConnections) {  
                    nlohmann::json roomData;
                    roomData["rid"] = rid;
                
                    /** Convert set to vector more efficiently */
                    std::vector<std::string> userKeys(users.begin(), users.end());
                
                    roomData["uid"] = std::move(userKeys);
                    data.push_back(std::move(roomData));
                }
            }

            /** Send the successful response with all banned connections */
            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res, data]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(data.dump());  /** Serialize the JSON response and send it */ 
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/users/messaging/disabled", [this](auto *res, auto *req) {
        /** Handle the request to fetch all disabled connections */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view apiKey = req->getHeader("api-key");

            /** Check if the API key is valid */
            if (apiKey != UserData::getInstance().adminApiKey) {

                /** Respond with 403 Unauthorized if the API key is invalid */
                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("403");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                    });
                }

                return;
            }

            /** Create and reserve space for the JSON response */
            nlohmann::json json_response = nlohmann::json::array();

            if(isMultiThread) {
                for (const auto& [rid, users] : ThreadSafe::disabledConnections) {  
                    /** Create a JSON object for the room */
                    nlohmann::json roomData;
                    roomData["rid"] = rid;
    
                    /** Store only the keys from the inner map */
                    std::vector<std::string> userKeys;
                    
                    for (const auto& [uid, _] : users) {  
                        userKeys.push_back(uid);
                    }
    
                    /** Convert vector to JSON array */
                    roomData["uid"] = std::move(userKeys);
    
                    /** Store the room data in the final list */
                    json_response.push_back(std::move(roomData));
                }
            } else {
                for (const auto& [rid, users] : SingleThreaded::disabledConnections) {  
                    nlohmann::json roomData;
                    roomData["rid"] = rid;
                
                    /** Convert set to vector more efficiently */
                    std::vector<std::string> userKeys(users.begin(), users.end());
                
                    roomData["uid"] = std::move(userKeys);
                    json_response.push_back(std::move(roomData));
                }                
            }
            
            /** Send the successful response with all banned connections */
            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res, json_response]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(json_response.dump());  /** Serialize the JSON response and send it */ 
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/messages/room/:rid", [this](auto *res, auto *req) {
        /** retrieve the messages for cache rooms (for other rooms no data will be returned) */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            std::string_view rid = req->getParameter("rid");
            std::string_view apiKey = req->getHeader("api-key");
            std::string_view uid = req->getHeader("uid");

            if(isMultiThread) {
                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor outer_accessor;

                if (!ThreadSafe::topics.find(outer_accessor, std::string(rid))) {
                    if(!*isAborted){
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
                        if(!*isAborted){
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
            } else {
                auto topicIt = SingleThreaded::topics.find(std::string(rid));
                if (topicIt == SingleThreaded::topics.end() || topicIt->second.find(std::string(uid)) == topicIt->second.end()) {
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

            write_worker(std::string(rid), "", true);

            if (apiKey != UserData::getInstance().clientApiKey) {

                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("403 Forbidden");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                    });
                }

                return;
            }

            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res, rid]() {
                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(read_worker(std::string(rid)));
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).del("/api/v1/database", [this](auto *res, auto *req) {
        /** delete all the data present in the LMDB database */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            /** Extract the API key from the request header */
            std::string_view apiKey = req->getHeader("api-key");

            /** Check if the provided API key is valid */
            if (apiKey != UserData::getInstance().adminApiKey) {

                /** Respond with 403 Forbidden if the API key is invalid */
                if(!*isAborted){
                    /** Increment the rejected request counter to track unauthorized access */
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("403 Forbidden");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Unauthorized access, Invalid API key!"})");
                    });
                }

                return;
            }

            MDB_txn* txn = nullptr;  /** Pointer for LMDB transaction */
            MDB_dbi dbi;  /** Handle for LMDB database */

            try {
                /** Begin a write transaction, avoid creating a new txn each time for efficiency */
                if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
                    throw std::runtime_error("Failed to begin transaction.");
                }

                /** Open the database only once and reuse the handle */
                if (mdb_dbi_open(txn, "messages_db", 0, &dbi) != 0) {
                    mdb_txn_abort(txn);  /** Abort transaction if database fails to open */
                    throw std::runtime_error("Failed to open database.");
                }

                /** Drop all keys in the database while keeping its structure */
                if (mdb_drop(txn, dbi, 0) != 0) {  /** Pass `0` to truncate the database */
                    mdb_txn_abort(txn);  /** Abort transaction if drop operation fails */
                    throw std::runtime_error("Failed to drop database.");
                }

                /** Commit the transaction to apply changes, keeping memory use low */
                if (mdb_txn_commit(txn) != 0) {
                    throw std::runtime_error("Failed to commit transaction.");
                }

                /** Respond with a success message */
                if(!*isAborted){
                    totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res]() {
                        res->writeStatus("200 OK");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Database truncated successfully!"})");
                    });
                }
            } catch (const std::exception& e) {
                /** Handle any errors efficiently without leaking resources */

                /** If an error occurs, make sure the transaction is aborted to free resources */
                if (txn) mdb_txn_abort(txn);

                /** Respond with the error message */
                if(!*isAborted){
                    totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                    res->cork([res, e]() {
                        res->writeStatus("500 Internal Server Error");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Internal server error!"})");
                    });
                }
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).get("/api/v1/ping", [](auto *res, auto */*req*/) {
        /** send pong as a response for ping */
        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            if(!*isAborted){
                totalSuccessApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("200 OK");
                    res->end("pong!");
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).any("/*", [](auto *res, auto */*req*/) {
        /** wildcard url to handle any random request */
        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
            totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);
        });

        try {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("404 Not Found");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "The requested resource is not found!"})");
                });
            }
        } catch (std::exception &e) {
            if(!*isAborted){
                totalFailedApiCalls.fetch_add(1, std::memory_order_relaxed);

                res->cork([res]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Internal server error!"})");
                });
            }
        }
	}).listen(PORT, [this](auto *token) {
    listen_socket_ = token;
    if (listen_socket_) {
        std::cout << "Thread " << std::this_thread::get_id() << " listening on port " << PORT << std::endl;
    }
    else {
        std::cout << "Thread " << std::this_thread::get_id() << " failed to listen on port " << PORT << std::endl;
    }
  });

  app_->run();

  /** cleanup */
  io_context.stop();

  std::cout << "Thread " << std::this_thread::get_id() << " exiting" << std::endl;
}

/**
 * Checks if the DNS for the given domain resolves to the expected IP address.
 *
 * @param domain The domain name to check.
 * @param expectedIP The expected IP address.
 * @return true if DNS resolves correctly, false otherwise.
 */
bool isDNSResolvedToIP(std::string_view domain, std::string_view expectedIP) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; /** IPv4 (use AF_UNSPEC for both IPv4 & IPv6) */ 

    /** Perform a DNS lookup */
    if (getaddrinfo(domain.data(), nullptr, &hints, &res) != 0) {
        return false;
    }

    char resolvedIP[INET_ADDRSTRLEN];
    bool matched = false;

    /** Iterate through resolved addresses */
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        inet_ntop(AF_INET, &addr->sin_addr, resolvedIP, INET_ADDRSTRLEN);
        
        /** Compare resolved IP with expected IP */
        if (expectedIP == resolvedIP) {
            matched = true;
            break;
        }
    }

    /** Free memory allocated by getaddrinfo */
    freeaddrinfo(res);
    return matched;
}

/**
 * Continuously checks DNS resolution until it matches the expected IP.
 *
 * @param domain The domain name to check.
 * @param expectedIP The expected IP address.
 */
void waitForCorrectDNS(std::string_view domain, std::string_view expectedIP) {
    std::cout << "Waiting for DNS resolution of " << domain << " to match " << expectedIP << "...\n";

    /** Keep checking until the DNS resolves correctly */
    while (!isDNSResolvedToIP(domain, expectedIP)) {
        std::cout << "DNS not resolved correctly. Retrying in 10 seconds...\n";
        std::this_thread::sleep_for(std::chrono::seconds(10)); /** Avoid excessive CPU usage */ 
    }

    std::cout << "DNS correctly resolved for " << domain << " to " << expectedIP << "!\n";
}

/**
 * Checks if an SSL certificate exists for the domain.
 *
 * @param domain The domain name.
 * @return true if the certificate exists, false otherwise.
 */
bool doesCertificateExist(std::string_view domain) {
    std::string certPath = "/home/socketlink/certbot-config/live/" + std::string(domain) + "/cert.pem";
    
    /** Check if the certificate file exists */
    struct stat buffer;
    return (stat(certPath.c_str(), &buffer) == 0);
}

/**
 * Checks if the SSL certificate for the domain is valid for at least the next 24 hours.
 *
 * @param domain The domain name.
 * @return true if the certificate is valid, false otherwise.
 */
bool isCertificateValid(std::string_view domain) {
    std::array<char, 128> buffer{};
    std::string checkCmd = "openssl x509 -checkend 86400 -noout -in /home/socketlink/certbot-config/live/" + std::string(domain) + "/cert.pem";

    /** Execute the command using popen */
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(checkCmd.c_str(), "r"), pclose);
    if (!pipe) {
        std::cerr << "Failed to check certificate validity.\n";
        return false;
    }

    /** Read the command output */
    if (fgets(buffer.data(), buffer.size(), pipe.get()) == nullptr) {
        std::cout << "Certificate expired or invalid for " << domain << ".\n";
        return false;
    }

    return true;
}

/**
 * Creates a new SSL certificate for the domain using Certbot.
 *
 * @param domain The domain name.
 */
void createCertificate(std::string_view domain) {
    std::cout << "Creating a new SSL certificate for " << domain << "...\n";
    std::string createCmd = "certbot certonly --standalone --non-interactive --agree-tos "
    "--email adisingh925@gmail.com --key-type ecdsa -d " + std::string(domain) + 
    " --config-dir /home/socketlink/certbot-config "
    "--work-dir /home/socketlink/certbot-work "
    "--logs-dir /home/socketlink/certbot-logs";
    std::system(createCmd.c_str());
}

/**
 * Renews the SSL certificate for the domain if necessary.
 *
 * @param domain The domain name.
 */
void renewCertificate(std::string_view domain) {
    std::cout << "Renewing SSL certificate for " << domain << "...\n";
    std::string renewCmd = 
    "certbot renew --quiet --non-interactive --preferred-challenges http "
    "--config-dir /home/socketlink/certbot-config "
    "--work-dir /home/socketlink/certbot-work "
    "--logs-dir /home/socketlink/certbot-logs";
    std::system(renewCmd.c_str());
}

/**
 * @brief Monitors the SSL certificate file for changes and restarts the server if modified.
 * 
 * This function runs in a separate thread and checks the last modified time of the certificate file 
 * once every 24 hours. If a change is detected, it restarts the `socketlink-client-backend.service`.
 */
void watchCertChanges(std::string_view domain) {
    /** 
     * Define the certificate file path that needs to be monitored for changes.
     */
    const std::string certPath = "/home/socketlink/certbot-config/live/" + std::string(domain) + "/fullchain.pem";

    /** 
     * Get the last modified time of the certificate file at startup.
     */
    std::filesystem::file_time_type lastModifiedTime = std::filesystem::last_write_time(certPath);

    while (true) {
        /** 
         * Sleep for 24 hours before checking the file again to minimize resource usage.
         */
        std::this_thread::sleep_for(std::chrono::hours(24));

        /** 
         * Get the current last modified time of the certificate file.
         */
        auto currentModifiedTime = std::filesystem::last_write_time(certPath);

        /**
         * If the file has been modified since the last check, restart the service.
         */
        if (currentModifiedTime != lastModifiedTime) {
            std::cout << "Certificate changed, restarting service...\n";

            /** 
             * Restart the server using systemd user service.
             */
            std::exit(0);
        }
    }
}

/* Main */
int main() {
    /** Fetch and populated data before starting the threads */
    fetchAndPopulateUserData();
    init_env();

    if(UserData::getInstance().subdomain.empty()){
        /** something is wrong with the data, restarting the server */
        std::exit(0);
    }

    std::string domain = UserData::getInstance().subdomain + ".socketlink.io";
    waitForCorrectDNS(domain, UserData::getInstance().ip);  

    if (!doesCertificateExist(domain))
    {
        std::cout << "No SSL certificate found. Creating a new one...\n";
        createCertificate(domain);
    }
    else if (!isCertificateValid(domain))
    {
        std::cout << "SSL certificate is expired. Renewing...\n";
        renewCertificate(domain);
    }
    else
    {
        std::cout << "SSL certificate is valid. No renewal needed.\n";
    }

    /** running the file change watcher thread */
    std::thread watcher(watchCertChanges, domain);
    watcher.detach();

    int numThreads = std::thread::hardware_concurrency();

    if (numThreads > 1)
    {
        isMultiThread = true;
    }

    workers.resize(numThreads);
    
    std::transform(workers.begin(), workers.end(), workers.begin(), [](worker_t &w) {
        w.thread_ = std::make_shared<std::thread>([&w]() {
            /* create uWebSocket worker and capture uWS::Loop, uWS::App objects. */
            w.work();
        });

        return w;
    });
    
    std::for_each(workers.begin(), workers.end(), [](worker_t &w) {
        w.thread_->join();
    });

    mdb_env_close(env);
    
    return 0;
}