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

    // Custom exception class for MySQL errors
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
            }

            conn = mysql_init(NULL);  /**< Initialize a new MySQL connection */
            if (!conn) {
                throw MySQLException("mysql_init() failed");
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
                throw MySQLException("mysql_real_connect() failed: " + std::string(mysql_error(conn)));
            } else {
                mysql_query(conn, "SET SESSION query_cache_type = OFF");  /**< Disable query caching */
                createTableIfNotExists();  /**< Create the table if it doesn't exist */
            }
        } catch (const MySQLException& e) {
            std::cerr << "MySQL Error: " << e.what() << std::endl;
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
            std::cerr << "Connection Error: " << e.what() << std::endl;
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
                "identifier VARCHAR(255) NOT NULL,"
                "room VARCHAR(255) NOT NULL"
                ")";

            if (mysql_query(conn, query)) {
                throw MySQLException("Table creation failed: " + std::string(mysql_error(conn)));
            }
        } catch (const MySQLException& e) {
            std::cerr << "Table Creation Error: " << e.what() << std::endl;
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
                batch_data.clear();  /**< Clear the batch data if empty */
                return false;
            }

            /** Build the query for batch insertion */
            std::string query = "INSERT INTO socketlink_messages (insert_time, message, identifier, room) VALUES ";
            for (size_t i = 0; i < batch_data.size(); ++i) {
                if (i > 0) query += ", ";
                query += "(?, ?, ?, ?)";
            }

            MYSQL_STMT* stmt = mysql_stmt_init(conn);  /**< Initialize the prepared statement */
            if (!stmt || mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
                throw MySQLException("Statement preparation failed: " + std::string(mysql_error(conn)));
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
                throw MySQLException("Batch insertion failed: " + std::string(mysql_stmt_error(stmt)));
            }

            mysql_stmt_close(stmt);  /**< Close the statement after execution */
            batch_data.clear();  /**< Clear the batch data after successful insertion */
            return true;
        } catch (const MySQLException& e) {
            std::cerr << "Batch Insertion Error: " << e.what() << std::endl;

            /** clearing the batch data */
            batch_data.clear();

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
            std::cerr << "Constructor Error: " << e.what() << std::endl;
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
            std::cerr << "Destructor Error: " << e.what() << std::endl;
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
            std::cerr << "Insert Data Error: " << e.what() << std::endl;
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
            std::cerr << "Flush Data Error: " << e.what() << std::endl;
        }
    }

    /**
     * Manually creates a connection to the database.
     */
    void manualCreateConnection() {
        try {
            createConnection();  /**< Manually create a connection to the database */
        } catch (const MySQLException& e) {
            std::cerr << "Manual Connection Error: " << e.what() << std::endl;
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
            std::cerr << "Disconnect Error: " << e.what() << std::endl;
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
    std::string rid;
    std::string key;
    std::string uid;

    /**
     * 0 - public
     * 1 - private
     * 2 - state public
     * 3 - state private
     */
    int roomType;

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
enum class Webhooks : uint64_t {
    /** Connection-related events */
    /** Triggered when a connection upgrade is rejected */
    ON_CONNECTION_UPGRADE_REJECTED = 1ULL << 0,            

    /** Message-related events */
    /** Triggered when a message is sent in a public room */
    ON_MESSAGE_PUBLIC_ROOM = 1ULL << 1,                    
    /** Triggered when a message is sent in a private room */
    ON_MESSAGE_PRIVATE_ROOM = 1ULL << 2,                   
    /** Triggered when a message is sent in a private state room */
    ON_MESSAGE_PUBLIC_STATE_ROOM = 1ULL << 3,             
    /** Triggered when a message is sent in a public state room */
    ON_MESSAGE_PRIVATE_STATE_ROOM = 1ULL << 4,              
    /** Triggered when a message is sent in a public cache room */
    ON_MESSAGE_PUBLIC_CACHE_ROOM = 1ULL << 5,              
    /** Triggered when a message is sent in a private cache room */
    ON_MESSAGE_PRIVATE_CACHE_ROOM = 1ULL << 6,             
    /** Triggered when a message is sent in a public state cache room */
    ON_MESSAGE_PUBLIC_STATE_CACHE_ROOM = 1ULL << 7,        
    /** Triggered when a message is sent in a private state cache room */
    ON_MESSAGE_PRIVATE_STATE_CACHE_ROOM = 1ULL << 8,       

    /** Common webhooks */
    /** Triggered when the rate limit is exceeded */
    ON_RATE_LIMIT_EXCEEDED = 1ULL << 9,                    
    /** Triggered when the rate limit is lifted */
    ON_RATE_LIMIT_LIFTED = 1ULL << 10,                     
    /** Triggered when a message is dropped */
    ON_MESSAGE_DROPPED = 1ULL << 11,                       
    /** Triggered when the monthly data transfer limit is exhausted */
    ON_MONTHLY_DATA_TRANSFER_LIMIT_EXHAUSTED = 1ULL << 12, 
    /** Triggered when a message size exceeds the allowed limit */
    ON_MESSAGE_SIZE_EXCEEDED = 1ULL << 13,                 
    /** Triggered when the maximum connection limit is reached */
    ON_MAX_CONNECTION_LIMIT_REACHED = 1ULL << 14,          
    /** Triggered when a verification request is initiated */
    ON_VERIFICATION_REQUEST = 1ULL << 15,                  

    /** Connection open events */
    /** Triggered when a connection opens in a public room */
    ON_CONNECTION_OPEN_PUBLIC_ROOM = 1ULL << 16,           
    /** Triggered when a connection opens in a private room */
    ON_CONNECTION_OPEN_PRIVATE_ROOM = 1ULL << 17,          
    /** Triggered when a connection opens in a private state room */
    ON_CONNECTION_OPEN_PUBLIC_STATE_ROOM = 1ULL << 18,    
    /** Triggered when a connection opens in a public state room */
    ON_CONNECTION_OPEN_PRIVATE_STATE_ROOM = 1ULL << 19,     
    /** Triggered when a connection opens in a public cache room */
    ON_CONNECTION_OPEN_PUBLIC_CACHE_ROOM = 1ULL << 20,     
    /** Triggered when a connection opens in a private cache room */
    ON_CONNECTION_OPEN_PRIVATE_CACHE_ROOM = 1ULL << 21,    
    /** Triggered when a connection opens in a public state cache room */
    ON_CONNECTION_OPEN_PUBLIC_STATE_CACHE_ROOM = 1ULL << 22, 
    /** Triggered when a connection opens in a private state cache room */
    ON_CONNECTION_OPEN_PRIVATE_STATE_CACHE_ROOM = 1ULL << 23, 

    /** Connection close events */
    /** Triggered when a connection closes in a public room */
    ON_CONNECTION_CLOSE_PUBLIC_ROOM = 1ULL << 24,          
    /** Triggered when a connection closes in a private room */
    ON_CONNECTION_CLOSE_PRIVATE_ROOM = 1ULL << 25,         
    /** Triggered when a connection closes in a private state room */
    ON_CONNECTION_CLOSE_PUBLIC_STATE_ROOM = 1ULL << 26,   
    /** Triggered when a connection closes in a public state room */
    ON_CONNECTION_CLOSE_PRIVATE_STATE_ROOM = 1ULL << 27,    
    /** Triggered when a connection closes in a public cache room */
    ON_CONNECTION_CLOSE_PUBLIC_CACHE_ROOM = 1ULL << 28,    
    /** Triggered when a connection closes in a private cache room */
    ON_CONNECTION_CLOSE_PRIVATE_CACHE_ROOM = 1ULL << 29,   
    /** Triggered when a connection closes in a public state cache room */
    ON_CONNECTION_CLOSE_PUBLIC_STATE_CACHE_ROOM = 1ULL << 30, 
    /** Triggered when a connection closes in a private state cache room */
    ON_CONNECTION_CLOSE_PRIVATE_STATE_CACHE_ROOM = 1ULL << 31, 

    /** Room occupancy events */
    /** Triggered when a public room becomes occupied */
    ON_ROOM_OCCUPIED_PUBLIC_ROOM = 1ULL << 32,             
    /** Triggered when a private room becomes occupied */
    ON_ROOM_OCCUPIED_PRIVATE_ROOM = 1ULL << 33,            
    /** Triggered when a private state room becomes occupied */
    ON_ROOM_OCCUPIED_PUBLIC_STATE_ROOM = 1ULL << 34,      
    /** Triggered when a public state room becomes occupied */
    ON_ROOM_OCCUPIED_PRIVATE_STATE_ROOM = 1ULL << 35,       
    /** Triggered when a public cache room becomes occupied */
    ON_ROOM_OCCUPIED_PUBLIC_CACHE_ROOM = 1ULL << 36,       
    /** Triggered when a private cache room becomes occupied */
    ON_ROOM_OCCUPIED_PRIVATE_CACHE_ROOM = 1ULL << 37,      
    /** Triggered when a public state cache room becomes occupied */
    ON_ROOM_OCCUPIED_PUBLIC_STATE_CACHE_ROOM = 1ULL << 38, 
    /** Triggered when a private state cache room becomes occupied */
    ON_ROOM_OCCUPIED_PRIVATE_STATE_CACHE_ROOM = 1ULL << 39, 

    /** Room vacancy events */
    /** Triggered when a public room becomes vacant */
    ON_ROOM_VACATED_PUBLIC_ROOM = 1ULL << 40,              
    /** Triggered when a private room becomes vacant */
    ON_ROOM_VACATED_PRIVATE_ROOM = 1ULL << 41,             
    /** Triggered when a private state room becomes vacant */
    ON_ROOM_VACATED_PUBLIC_STATE_ROOM = 1ULL << 42,       
    /** Triggered when a public state room becomes vacant */
    ON_ROOM_VACATED_PRIVATE_STATE_ROOM = 1ULL << 43,        
    /** Triggered when a public cache room becomes vacant */
    ON_ROOM_VACATED_PUBLIC_CACHE_ROOM = 1ULL << 44,        
    /** Triggered when a private cache room becomes vacant */
    ON_ROOM_VACATED_PRIVATE_CACHE_ROOM = 1ULL << 45,       
    /** Triggered when a public state cache room becomes vacant */
    ON_ROOM_VACATED_PUBLIC_STATE_CACHE_ROOM = 1ULL << 46,  
    /** Triggered when a private state cache room becomes vacant */
    ON_ROOM_VACATED_PRIVATE_STATE_CACHE_ROOM = 1ULL << 47  
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
std::atomic<unsigned long long> totalRejectedRquests{0};
std::atomic<double> averagePayloadSize{0.0};
std::atomic<double> averageLatency{0.0};
std::atomic<unsigned long long> droppedMessages{0};
std::atomic<unsigned int> messageCount(0);

/** these variables stores some userdata */
tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> topics;
tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> bannedConnections;
tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>> disabledConnections;
tbb::concurrent_hash_map<std::string, bool> uid;
std::atomic<bool> isMessagingDisabled(false);
tbb::concurrent_hash_map<std::string, WebSocketData> connections;

/** map to store enabled webhooks and features (no need to make it thread safe) */
std::unordered_map<Webhooks, int> webhookStatus;
std::unordered_map<Features, int> featureStatus;

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

/** is logs enabled */
constexpr bool LOGS_ENABLED = false;

/** HMAC-SHA256 Constants */
constexpr int HMAC_SHA256_DIGEST_LENGTH = 32;  /**< SHA-256 produces a 32-byte (256-bit) output */

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

/** log the sata in the console */
void log(const std::string& message) {
    if (LOGS_ENABLED) {
        std::cout << message << std::endl;
    }
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
void write_worker(const std::string& room_id, const std::string& user_id, const std::string& message_content, bool needsCommit = false) {
    MDB_txn* txn;
    MDB_dbi dbi;

    /** Batch to store messages before writing them to the database */
    static std::vector<std::tuple<std::string, std::string>> batch;

    /** Collect writes in a batch if commit is not immediately required */
    if (!needsCommit) {
        /** Get the current timestamp in milliseconds */
        auto timestamp = std::chrono::system_clock::now().time_since_epoch();
        auto timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp).count();
        std::string timestamp_str = std::to_string(timestamp_ms);

        /** Create the key format: room_id:timestamp:user_id */
        std::string combined_key = room_id + ":" + timestamp_str + ":" + user_id;

        /** Add the key-value pair to the batch */
        batch.push_back({combined_key, message_content});
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
        }

        /** Clear the batch after a successful commit */
        batch.clear();

        /** Close the database handle */
        mdb_dbi_close(env, dbi);
    }
}

/** this function will delete all the entries for a room */
void delete_worker(const std::string& room_id) {
    MDB_txn* txn;
    MDB_dbi dbi;
    MDB_cursor* cursor;

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

    /** Open a cursor to iterate over keys */
    if (mdb_cursor_open(txn, dbi, &cursor) != 0) {
        std::cerr << "Failed to open cursor.\n";
        mdb_txn_abort(txn);
        return;
    }

    MDB_val key, value;
    int rc = mdb_cursor_get(cursor, &key, &value, MDB_FIRST);

    /** Iterate through the database and delete all keys that match the room_id prefix */
    while (rc == 0) {
        std::string key_str(static_cast<char*>(key.mv_data), key.mv_size);
        
        /** Check if the key starts with room_id */
        if (key_str.find(room_id + ":") == 0) {
            if (mdb_del(txn, dbi, &key, nullptr) != 0) {
                std::cerr << "Failed to delete key: " << key_str << "\n";
                mdb_cursor_close(cursor);
                mdb_txn_abort(txn);
                return;
            }
        }
        
        rc = mdb_cursor_get(cursor, &key, &value, MDB_NEXT);
    }

    /** Commit the transaction after deletion */
    if (mdb_txn_commit(txn) != 0) {
        std::cerr << "Failed to commit delete transaction.\n";
    }

    /** Close cursor and database handle */
    mdb_cursor_close(cursor);
    mdb_dbi_close(env, dbi);
}

/** read the data from the LMDB */
std::string read_worker(const std::string& room_id, int n, int m) {
    MDB_txn* txn;  /** Transaction handle */
    MDB_dbi dbi;   /** Database handle */
    MDB_cursor* cursor;  /** Cursor for iterating through the database */

    std::ostringstream result;  /** Output stream to accumulate messages in JSON format */

    /** Start a read-only transaction */
    if (mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn) != 0) {
        std::cerr << "Failed to begin read transaction: " << mdb_strerror(errno) << "\n";
        return "[]";  /** Return empty JSON array on failure */
    }

    /** Open the common database for all rooms */
    if (mdb_dbi_open(txn, "messages_db", 0, &dbi) != 0) {
        std::cerr << "Failed to open database: " << mdb_strerror(errno) << "\n";
        mdb_txn_abort(txn);  /** Abort the transaction if opening the database fails */
        return "[]";  /** Return empty JSON array on failure */
    }

    /** Open a cursor to iterate through the database */
    if (mdb_cursor_open(txn, dbi, &cursor) != 0) {
        std::cerr << "Failed to open cursor: " << mdb_strerror(errno) << "\n";
        mdb_txn_abort(txn);  /** Abort the transaction if opening the cursor fails */
        mdb_dbi_close(env, dbi);  /** Close the database handle */
        return "[]";  /** Return empty JSON array on failure */
    }

    MDB_val key, value;  /** Key-value pair to store the retrieved data */
    int messages_skipped = 0;  /** Counter for skipped messages */
    int messages_read = 0;  /** Counter for read messages */

    /** Construct the prefix for the given room_id */
    std::string room_prefix = room_id + ":";

    /** Position the cursor at the last key in the database */
    if (mdb_cursor_get(cursor, &key, &value, MDB_LAST) == 0) {
        /** Skip messages for the specified room_id until `m` messages are skipped */
        while (messages_skipped < m) {
            std::string key_str((char*)key.mv_data, key.mv_size);

            /** Only consider keys that match the `room_id` prefix */
            if (key_str.find(room_prefix) == 0) {
                messages_skipped++;
            }

            /** Break if the desired number of messages have been skipped */
            if (messages_skipped >= m) break;

            /** Move to the previous key */
            if (mdb_cursor_get(cursor, &key, &value, MDB_PREV) != 0) break;
        }

        /** If offset `m` is larger than the number of messages, return an empty JSON array */
        if (messages_skipped < m) {
            mdb_cursor_close(cursor);
            mdb_dbi_close(env, dbi);
            mdb_txn_abort(txn);
            return "[]";
        }

        /** Start JSON array */
        result << "[\n";

        /** Read the next `n` messages */
        while (messages_read < n) {
            std::string key_str((char*)key.mv_data, key.mv_size);

            /** Only consider keys that match the `room_id` prefix */
            if (key_str.find(room_prefix) == 0) {
                /** Extract metadata from the key */
                size_t first_colon = key_str.find(':');
                size_t second_colon = key_str.find(':', first_colon + 1);
                std::string timestamp_str = key_str.substr(first_colon + 1, second_colon - first_colon - 1);
                std::string user_id = key_str.substr(second_colon + 1);

                /** Append message JSON to result */
                result << "  {\n";
                result << "    \"timestamp\": \"" << timestamp_str << "\",\n";
                result << "    \"message\": \"" << std::string((char*)value.mv_data, value.mv_size) << "\",\n";
                result << "    \"uid\": \"" << user_id << "\"\n";
                result << "  }";

                messages_read++;
                if (messages_read < n) result << ",\n";  /** Add a comma if not the last message */
            }

            /** Move to the previous key */
            if (mdb_cursor_get(cursor, &key, &value, MDB_PREV) != 0) break;
        }

        /** End JSON array */
        result << "\n]";
    } else {
        std::cerr << "No messages found for the given room_id.\n";
        result << "[]";  /** Return an empty JSON array if no messages were found */
    }

    /** Commit the transaction */
    if (mdb_txn_commit(txn) != 0) {
        std::cerr << "Failed to commit transaction: " << mdb_strerror(errno) << "\n";
    }

    /** Close the cursor and database handle */
    mdb_cursor_close(cursor);
    mdb_dbi_close(env, dbi);

    /** Return the JSON string */
    return result.str();
}

/** Function to populate the global unordered_map with active (1) and inactive (0) statuses */
void populateWebhookStatus(uint64_t bitmask)
{
    /** Clear the existing statuses in case this is called multiple times */
    webhookStatus.clear();

    for (uint64_t i = 0; i < 48; ++i)  // Use uint64_t to match bitmask size
    {
        /** Compute the webhook flag for this index */
        Webhooks webhook = static_cast<Webhooks>(static_cast<uint64_t>(1) << i);
        
        /** Store the webhook status based on the bitmask */
        webhookStatus[webhook] = (bitmask & (static_cast<uint64_t>(1) << i)) ? 1 : 0;
    }
}

/** Populate the enabled features */
void populateFeatureStatus(uint32_t bitmask)
{
    /** Clear the existing statuses in case this is called multiple times */
    featureStatus.clear();

    for (uint32_t i = 0; i < 1; ++i)
    {
        Features feature = static_cast<Features>(1 << i);
        featureStatus[feature] = (bitmask & (1 << i)) ? 1 : 0;
    }
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
void sendHTTPSPOSTRequestFireAndForget(
    const std::string& baseURL, 
    const std::string& path, 
    const std::string& body, 
    const std::map<std::string, std::string>& headers = {}
) {
    try {
        /** Disable SSL certificate verification if needed. 
         *  This is insecure and should only be used for testing purposes. */
        if(UserData::getInstance().webhookIP.empty()){
            /** DNS is not resolved, returning */
            return;
        }

        ssl_context.set_verify_mode(boost::asio::ssl::verify_none);

        if (!ssl_socket || !ssl_socket->lowest_layer().is_open()) {  
            ssl_socket = std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(io_context, ssl_context);
            
            /** if the request cannot be delivered immediately it will be dropped */
            ssl_socket->lowest_layer().non_blocking(true);  

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

        if(UserData::getInstance().webhookSecret.length() > 0){
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
    } catch (const boost::system::system_error& e) {
        if (e.code() == boost::asio::error::broken_pipe) {
            /** broken pipe error, resending */
            ssl_socket = nullptr;  

            /** dangerous retry */
            /* sendHTTPSPOSTRequestFireAndForget(baseURL, path, body, headers); */
        } else if (e.code() == boost::asio::error::connection_reset) {
            /** connection reset by peer */
            ssl_socket = nullptr;

            /** dangerous retry */
            /* sendHTTPSPOSTRequestFireAndForget(baseURL, path, body, headers); */
        } else {
            /** some other error has occurred */
        }
    }
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
        userData.webhooks = parsedJson["webhooks"].get<uint64_t>();
    }

    if (parsedJson.contains("features") && !parsedJson["features"].is_null()) {
        userData.features = parsedJson["features"].get<uint32_t>();
    }

    if (parsedJson.contains("webhook_base_url") && !parsedJson["webhook_base_url"].is_null()) {
        userData.webHookBaseUrl = parsedJson["webhook_base_url"].get<std::string>();
    }

    if (parsedJson.contains("webhook_path") && !parsedJson["webhook_path"].is_null()) {
        userData.webhookPath = parsedJson["webhook_path"].get<std::string>();
    }

    if (parsedJson.contains("webhook_secret") && !parsedJson["webhook_secret"].is_null()) {
        userData.webhookSecret = parsedJson["webhook_secret"].get<std::string>();
    }

    if(parsedJson.contains("max_storage_allowed_in_gb") && !parsedJson["max_storage_allowed_in_gb"].is_null()){
        userData.lmdbDatabaseSizeInBytes = parsedJson["max_storage_allowed_in_gb"].get<unsigned long long>();
    }

    if(parsedJson.contains("lmdb_commit_batch_size") && !parsedJson["lmdb_commit_batch_size"].is_null()){
        userData.lmdbCommitBatchSize = parsedJson["lmdb_commit_batch_size"].get<int>();
    }

    if(parsedJson.contains("db_commit_batch_size") && !parsedJson["db_commit_batch_size"].is_null()){
        userData.mysqlDBCommitBatchSize = parsedJson["db_commit_batch_size"].get<int>();
    }

    if(parsedJson.contains("idle_timeout_in_seconds") && !parsedJson["idle_timeout_in_seconds"].is_null()){
        userData.idleTimeoutInSeconds = parsedJson["idle_timeout_in_seconds"].get<unsigned short>();
    }

    if(parsedJson.contains("max_lifetime_in_minutes") && !parsedJson["max_lifetime_in_minutes"].is_null()){
        userData.maxLifetimeInMinutes = parsedJson["max_lifetime_in_minutes"].get<unsigned short>();
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

    if(is_sql_integration_enabled == 1){
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

                featureStatus[Features::ENABLE_MYSQL_INTEGRATION] = 1;
                needsDBUpdate = 1;
            } else {
                featureStatus[Features::ENABLE_MYSQL_INTEGRATION] = 1;
                needsDBUpdate = 1;
            }
        } else {
            featureStatus[Features::ENABLE_MYSQL_INTEGRATION] = 0;
            needsDBUpdate = 1;
        }
    }
    else if (is_sql_integration_enabled == -1)
    {
        featureStatus[Features::ENABLE_MYSQL_INTEGRATION] = 0;
        needsDBUpdate = -1;
    }

    /** store payload sent */
    if (parsedJson.contains("total_payload_sent")) {
        totalPayloadSent = parsedJson["total_payload_sent"].get<unsigned long long>();
    }

    /** populate enabled webhooks and features */
    populateWebhookStatus(UserData::getInstance().webhooks);

    /** resolve and store the IP address of the client's webhook URL */
    resolveAndStoreIPAddress(UserData::getInstance().webHookBaseUrl);

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
void closeConnection(uWS::WebSocket<true, true, PerSocketData>* ws, worker_t* worker) {
    std::string rid = ws->getUserData()->rid;

    /** Unsubscribe the user from the room */
    if (!rid.empty()) {
        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor outer_accessor;

        int size = 0;

        /** Check if the room exists in the topics map */
        if (topics.find(outer_accessor, rid)) {
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
                topics.erase(outer_accessor);

                /** Remove disabled and banned connections */
                for (auto& map : {&disabledConnections, &bannedConnections}) {
                    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor map_accessor;
                    if (map->find(map_accessor, rid)) {
                        map->erase(map_accessor);
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

        /** Broadcast disconnect message */
        static const std::unordered_set<uint8_t> validRoomTypes = {
            static_cast<uint8_t>(Rooms::PUBLIC_STATE),
            static_cast<uint8_t>(Rooms::PRIVATE_STATE),
            static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE),
            static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)
        };

        if (validRoomTypes.count(ws->getUserData()->roomType)) {
            std::string result = R"({"event":"SOMEONE_LEFT_THE_ROOM", "uid":")" + ws->getUserData()->uid + R"("})";

            /** Publish message to all workers */
            for (auto& w : ::workers) {
                w.loop_->defer([&w, rid, result]() {
                    w.app_->publish(rid, result, uWS::OpCode::TEXT, true);
                });
            }
        }

        /** connection close webhooks */
        switch(ws->getUserData()->roomType) {
            case static_cast<uint8_t>(Rooms::PUBLIC) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PUBLIC_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_CLOSE_PUBLIC_ROOM\", "
                            << "\"code\":5025, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }  

            case static_cast<uint8_t>(Rooms::PRIVATE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PRIVATE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_CLOSE_PRIVATE_ROOM\", "
                            << "\"code\":5026, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PUBLIC_STATE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PUBLIC_STATE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_CLOSE_PUBLIC_STATE_ROOM\", "
                            << "\"code\":5027, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str();

                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PRIVATE_STATE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PRIVATE_STATE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_CLOSE_PRIVATE_STATE_ROOM\", "
                            << "\"code\":5028, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PUBLIC_CACHE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PUBLIC_CACHE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_CLOSE_PUBLIC_CACHE_ROOM\", "
                            << "\"code\":5029, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PRIVATE_CACHE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PRIVATE_CACHE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_CLOSE_PRIVATE_CACHE_ROOM\", "
                            << "\"code\":5030, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PUBLIC_STATE_CACHE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_CLOSE_PUBLIC_STATE_CACHE_ROOM\", "
                            << "\"code\":5031, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PRIVATE_STATE_CACHE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_CLOSE_PRIVATE_STATE_CACHE_ROOM\", "
                            << "\"code\":5032, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }
        }

        /** room vacate webhooks */
        if (size == 0) {
            switch(ws->getUserData()->roomType) {
                case static_cast<uint8_t>(Rooms::PUBLIC) : {
                    if(webhookStatus[Webhooks::ON_ROOM_VACATED_PUBLIC_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_VACATED_PUBLIC_ROOM\", "
                                << "\"code\":5033, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }  

                case static_cast<uint8_t>(Rooms::PRIVATE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_VACATED_PRIVATE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_VACATED_PRIVATE_ROOM\", "
                                << "\"code\":5034, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PUBLIC_STATE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_VACATED_PUBLIC_STATE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_VACATED_PUBLIC_STATE_ROOM\", "
                                << "\"code\":5035, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str();

                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PRIVATE_STATE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_VACATED_PRIVATE_STATE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_VACATED_PRIVATE_STATE_ROOM\", "
                                << "\"code\":5036, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PUBLIC_CACHE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_VACATED_PUBLIC_CACHE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_VACATED_PUBLIC_CACHE_ROOM\", "
                                << "\"code\":5037, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PRIVATE_CACHE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_VACATED_PRIVATE_CACHE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_VACATED_PRIVATE_CACHE_ROOM\", "
                                << "\"code\":5038, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_VACATED_PUBLIC_STATE_CACHE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_VACATED_PUBLIC_STATE_CACHE_ROOM\", "
                                << "\"code\":5039, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_VACATED_PRIVATE_STATE_CACHE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_VACATED_PRIVATE_STATE_CACHE_ROOM\", "
                                << "\"code\":5040, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }
            }
        }
    }
}

/** subscribe to a new room */
void openConnection(uWS::WebSocket<true, true, PerSocketData>* ws, worker_t* worker) {
    if (!ws->getUserData()->rid.empty()) {
    const auto& rid = ws->getUserData()->rid;
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

    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor topicsAccessor;
    int size = 0;

    /** Insert user into topics map */
    if (topics.find(topicsAccessor, rid)) {
        /** Room exists, add UID if not present */
        auto& innerMap = topicsAccessor->second;
        tbb::concurrent_hash_map<std::string, bool>::accessor innerAccessor;
        if (!innerMap.find(innerAccessor, uid)) {
            innerMap.insert(innerAccessor, uid);
            innerAccessor->second = true;
        }
        size = innerMap.size();
    } else {
        /** Room does not exist, create a new entry */
        tbb::concurrent_hash_map<std::string, bool> newInnerMap;
        newInnerMap.insert({uid, true});
        topics.insert(topicsAccessor, rid);
        topicsAccessor->second = std::move(newInnerMap);
        size = 1;
    }

    /** Send a message to self */
    std::string selfMessage = "{\"event\":\"CONNECTED_TO_ROOM\", \"uid\":\"" + uid + "\"}";

    if (workerThreadId == currentThreadId) {
        ws->send(selfMessage, uWS::OpCode::TEXT, true);
    } else {
        worker->loop_->defer([ws, selfMessage]() {
            ws->send(selfMessage, uWS::OpCode::TEXT, true);
        });
    }

    /** Broadcast the message to others if the room is public/private */
    if (ws->getUserData()->roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE) ||
        ws->getUserData()->roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE) ||
        ws->getUserData()->roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) ||
        ws->getUserData()->roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)) {
        
            std::string broadcastMessage = "{\"event\":\"SOMEONE_JOINED_THE_ROOM\", \"uid\":\"" + uid + "\"}";

            for (auto& w : ::workers) {
                if (workerThreadId == w.thread_->get_id()) {
                    ws->publish(rid, broadcastMessage, uWS::OpCode::TEXT, true);
                } else {
                    w.loop_->defer([&w, &ws, rid, broadcastMessage]() {
                        w.app_->publish(rid, broadcastMessage, uWS::OpCode::TEXT, true);
                    });
                }
            }
        }

        /** fire connection open webhook */
        switch(ws->getUserData()->roomType) {
            case static_cast<uint8_t>(Rooms::PUBLIC) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PUBLIC_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_OPEN_PUBLIC_ROOM\", "
                            << "\"code\":5001, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }  

            case static_cast<uint8_t>(Rooms::PRIVATE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PRIVATE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_OPEN_PRIVATE_ROOM\", "
                            << "\"code\":5002, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PUBLIC_STATE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PUBLIC_STATE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_OPEN_PUBLIC_STATE_ROOM\", "
                            << "\"code\":5003, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str();

                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PRIVATE_STATE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PRIVATE_STATE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_OPEN_PRIVATE_STATE_ROOM\", "
                            << "\"code\":5004, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PUBLIC_CACHE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PUBLIC_CACHE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_OPEN_PUBLIC_CACHE_ROOM\", "
                            << "\"code\":5005, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PRIVATE_CACHE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PRIVATE_CACHE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_OPEN_PRIVATE_CACHE_ROOM\", "
                            << "\"code\":5006, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PUBLIC_STATE_CACHE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_OPEN_PUBLIC_STATE_CACHE_ROOM\", "
                            << "\"code\":5007, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }

            case static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE) : {
                if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PRIVATE_STATE_CACHE_ROOM] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_OPEN_PRIVATE_STATE_CACHE_ROOM\", "
                            << "\"code\":5008, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                            << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                            << "\"connections_in_room\":\"" << size << "\", "
                            << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
                break;
            }
        }

        /** Room ocuupied webhooks */
        if(size == 1){            
            switch(ws->getUserData()->roomType) {
                case static_cast<uint8_t>(Rooms::PUBLIC) : {                    
                    if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PUBLIC_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_OCCUPIED_PUBLIC_ROOM\", "
                                << "\"code\":5009, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }  

                case static_cast<uint8_t>(Rooms::PRIVATE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PRIVATE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_OCCUPIED_PRIVATE_ROOM\", "
                                << "\"code\":5010, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PUBLIC_STATE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PUBLIC_STATE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_OCCUPIED_PUBLIC_STATE_ROOM\", "
                                << "\"code\":5011, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str();

                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PRIVATE_STATE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PRIVATE_STATE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_OCCUPIED_PRIVATE_STATE_ROOM\", "
                                << "\"code\":5012, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PUBLIC_CACHE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PUBLIC_CACHE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_OCCUPIED_PUBLIC_CACHE_ROOM\", "
                                << "\"code\":5013, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PRIVATE_CACHE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PRIVATE_CACHE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_OCCUPIED_PRIVATE_CACHE_ROOM\", "
                                << "\"code\":5014, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PUBLIC_STATE_CACHE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_OCCUPIED_PUBLIC_STATE_CACHE_ROOM\", "
                                << "\"code\":5015, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }

                case static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE) : {
                    if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PRIVATE_STATE_CACHE_ROOM] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_ROOM_OCCUPIED_PRIVATE_STATE_CACHE_ROOM\", "
                                << "\"code\":5016, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"connections_in_room\":\"" << size << "\", "
                                << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                    break;
                }
            }
        }
    }
}

/**
 * HTTP Webhook Error Codes
 * 
 *************** ON_CONNECTION_UPGRADE_REJECTED ****************************
 * 
 * UID_BANNED_GLOBALLY - 3580
 * MAX_CONNECTION_LIMIT_REACHED - 3982
 * INVALID_API_KEY - 3203
 * UID_ALREADY_EXIST - 3780
 * EMPTY_UID - 3291
 * 
 ********************** ON_ROOM_UPDATE **************************************
 * 
 * UID_BANNED_ON_ROOM - 3371
 * INVALID_ROOM_ID_LENGTH - 3484
 * INVALID_ROOM_TYPE - 3925
 * ON_VERIFICATION_REQUEST_WEBHOOK_DISABLED - 3376
 * UID_NOT_FOUND - 3910
 * ROOM_ACCESS_DENIED - 3511
 * 
 ****************** LIMITS_EXCEEDED *************************

 * ON_RATE_LIMIT_EXCEEDED - 3237
 * ON_MONTHLY_DATA_TRANSFER_LIMIT_EXHAUSTED - 3758
 * ON_MESSAGE_SIZE_EXCEEDED - 3349
 * 
 ***************** SUCCESS *********************** 
 *
 * ON_ROOM_SUCCESSFULLY_UPDATED - 7481
 * 
 ***************** ERROR_CODES ******************
 *
 * INVALID_JSON - 8931
 * 
 ************************* VERIFICATION_CODES ***************************
 * 
 * INIT
 * 
 * INIT_PRIVATE_ROOM_VERIFICATION - 4001
 * INIT_PRIVATE_STATE_ROOM_VERIFICATION - 4002
 * INIT_PRIVATE_CACHE_ROOM_VERIFICATION - 4003
 * INIT_PRIVATE_STATE_CACHE_ROOM_VERIFICATION - 4004
 * 
 * Connection / Disconnection Codes
 * 
 * ON_CONNECTION_OPEN_PUBLIC_ROOM - 5001
 * ON_CONNECTION_OPEN_PRIVATE_ROOM - 5002
 * ON_CONNECTION_OPEN_PUBLIC_STATE_ROOM - 5003
 * ON_CONNECTION_OPEN_PRIVATE_STATE_ROOM - 5004
 * ON_CONNECTION_OPEN_PUBLIC_CACHE_ROOM - 5005
 * ON_CONNECTION_OPEN_PRIVATE_CACHE_ROOM - 5006
 * ON_CONNECTION_OPEN_PUBLIC_STATE_CACHE_ROOM - 5007
 * ON_CONNECTION_OPEN_PRIVATE_STATE_CACHE_ROOM - 5008
 * 
 * ON_ROOM_OCCUPIED_PUBLIC_ROOM - 5009
 * ON_ROOM_OCCUPIED_PRIVATE_ROOM - 5010
 * ON_ROOM_OCCUPIED_PUBLIC_STATE_ROOM - 5011
 * ON_ROOM_OCCUPIED_PRIVATE_STATE_ROOM - 5012
 * ON_ROOM_OCCUPIED_PUBLIC_CACHE_ROOM - 5013
 * ON_ROOM_OCCUPIED_PRIVATE_CACHE_ROOM - 5014
 * ON_ROOM_OCCUPIED_PUBLIC_STATE_CACHE_ROOM - 5015
 * ON_ROOM_OCCUPIED_PRIVATE_STATE_CACHE_ROOM - 5016
 * 
 * ON_MESSAGE_PUBLIC_ROOM - 5017
 * ON_MESSAGE_PRIVATE_ROOM - 5018
 * ON_MESSAGE_PUBLIC_STATE_ROOM - 5019
 * ON_MESSAGE_PRIVATE_STATE_ROOM - 5020
 * ON_MESSAGE_PUBLIC_CACHE_ROOM - 5021
 * ON_MESSAGE_PRIVATE_CACHE_ROOM - 5022
 * ON_MESSAGE_PUBLIC_STATE_CACHE_ROOM - 5023
 * ON_MESSAGE_PRIVATE_STATE_CACHE_ROOM - 5024
 * 
 * ON_CONNECTION_CLOSE_PUBLIC_ROOM - 5025
 * ON_CONNECTION_CLOSE_PRIVATE_ROOM - 5026
 * ON_CONNECTION_CLOSE_PUBLIC_STATE_ROOM - 5027
 * ON_CONNECTION_CLOSE_PRIVATE_STATE_ROOM - 5028
 * ON_CONNECTION_CLOSE_PUBLIC_CACHE_ROOM - 5029
 * ON_CONNECTION_CLOSE_PRIVATE_CACHE_ROOM - 5030
 * ON_CONNECTION_CLOSE_PUBLIC_STATE_CACHE_ROOM - 5031
 * ON_CONNECTION_CLOSE_PRIVATE_STATE_CACHE_ROOM - 5032
 * 
 * ON_ROOM_VACATED_PUBLIC_ROOM - 5033
 * ON_ROOM_VACATED_PRIVATE_ROOM - 5034
 * ON_ROOM_VACATED_PUBLIC_STATE_ROOM - 5035
 * ON_ROOM_VACATED_PRIVATE_STATE_ROOM - 5036
 * ON_ROOM_VACATED_PUBLIC_CACHE_ROOM - 5037
 * ON_ROOM_VACATED_PRIVATE_CACHE_ROOM - 5038
 * ON_ROOM_VACATED_PUBLIC_STATE_CACHE_ROOM - 5039
 * ON_ROOM_VACATED_PRIVATE_STATE_CACHE_ROOM - 5040
 * 
 ********************** INFO *******************************
 * 
 * ON_RATE_LIMIT_LIFTED - 6001
 * ON_MESSAGE_DROPPED - 6002
 * 
 */

/* uWebSocket worker thread function. */
void worker_t::work()
{
    const std::string keyFilePath = "/etc/letsencrypt/live/" + UserData::getInstance().subdomain + ".socketlink.io/privkey.pem";
    const std::string certFileName = "/etc/letsencrypt/live/" + UserData::getInstance().subdomain + ".socketlink.io/fullchain.pem";

  /* Every thread has its own Loop, and uWS::Loop::get() returns the Loop for current thread.*/ 
  loop_ = uWS::Loop::get();

  /* uWS::App object / instance is used in uWS::Loop::defer(lambda_function) */
  app_ = std::make_shared<uWS::SSLApp>(
    uWS::SSLApp({
        .key_file_name = keyFilePath.c_str(),
        .cert_file_name = certFileName.c_str(),
        .ssl_prefer_low_memory_usage = true,
    })
  );

  db_handler = std::make_unique<MySQLConnectionHandler>();

  /* Very simple WebSocket broadcasting echo server */
  app_->ws<PerSocketData>("/*", {
    /* Settings */
    .compression = uWS::SHARED_COMPRESSOR,
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
            std::string(req->getHeader("uid").empty() ? req->getHeader("sec-websocket-key") : req->getHeader("uid")),
            context,
            res
        };

        res->onAborted([=]() {
            upgradeData->aborted = true;
        });

        if(upgradeData->uid == upgradeData->secWebSocketKey){
            /** check if the connection is banned */
            if (webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1) {
                res->writeStatus("403 Forbidden");
                res->writeHeader("Content-Type", "application/json");
                res->end("EMPTY_UID");

                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"EMPTY_UID\", "
                        << "\"code\":3291, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"message\":\"uid cannot be empty!\"}";

                std::string body = payload.str();

                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            }
        }

        /** Check if the user is banned and reject the connection */
        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor bannedAccessor;
        if (bannedConnections.find(bannedAccessor, "global")) {
            /** Access the inner map */
            tbb::concurrent_hash_map<std::string, bool>& inner_map = bannedAccessor->second;

            /** Accessor for the inner map */
            tbb::concurrent_hash_map<std::string, bool>::accessor innerAccessor;
            
            /** Check if the user UID is banned in the inner map */
            if (inner_map.find(innerAccessor, upgradeData->uid)) {
                totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
                res->writeStatus("403 Forbidden");
                res->writeHeader("Content-Type", "application/json");
                res->end("CONNECTION_BANNED");

                /** check if the connection is banned */
                if (webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1) {
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                            << "\"trigger\":\"UID_BANNED_GLOBALLY\", "
                            << "\"code\":3580, "
                            << "\"uid\":\"" << upgradeData->uid << "\", "
                            << "\"message\":\"This connection is globally banned by the admin!\"}";

                    std::string body = payload.str();

                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }

                return;
            }
        }

        /** check if a connection is already there with the same uid (thread safe) */
        tbb::concurrent_hash_map<std::string, bool>::const_accessor accessor;
        if(uid.find(accessor, upgradeData->uid)){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403 Forbidden")->end("UID_ALREADY_EXIST");

            if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"UID_ALREADY_EXIST\", "  
                        << "\"code\":3780, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"message\":\"There is already a connection using this UID!\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            }

            return;
        }

        /** Check if the connection limit has been exceeded */
        if (globalConnectionCounter.load(std::memory_order_relaxed) >= UserData::getInstance().connections) {
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403 Forbidden")->end("MAX_CONNECTION_LIMIT_REACHED");

            if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"MAX_CONNECTION_LIMIT_REACHED\", "  
                        << "\"code\":3982, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"message\":\"You have reached the max limit of allowed connections!\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            }

            return;
        }

        /** Check if API key is valid or not */
        if(UserData::getInstance().clientApiKey != upgradeData->key){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403 Forbidden")->end("INVALID_API_KEY");

            if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"INVALID_API_KEY\", "  
                        << "\"code\":3203, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"message\":\"The API key is invalid!\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            }

            return;
        }

        if (!upgradeData->aborted) {
            upgradeData->httpRes->cork([upgradeData]() {
                upgradeData->httpRes->template upgrade<PerSocketData>({
                    /* We initialize PerSocketData struct here */
                    .key = upgradeData->key,
                    .uid = upgradeData->uid,
                    .roomType = 255,  
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

        /** Thread-safe insertion into connections map */
        tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
        bool inserted = connections.insert(conn_accessor, userId);
        if (inserted) {
            conn_accessor->second = std::move(data);
        } else {
            /** UID already exists, something went wrong */
            ws->end();
            return;
        }

        /** Increment global connection counter */
        globalConnectionCounter.fetch_add(1, std::memory_order_relaxed);

        /** Thread-safe insertion into uid map */
        tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;
        if (uid.insert(user_accessor, userId)) {
            user_accessor->second = true;
        } else {
            /** UID already exists, something went wrong */
            ws->end();
            return;
        }

        /** Subscribe to channels */
        ws->subscribe(userId);
        ws->subscribe(BROADCAST);
    },
    .message = [this](auto *ws, std::string_view message, uWS::OpCode opCode) {
        auto& userData = *ws->getUserData();
        auto uid = userData.uid;
        auto rid = userData.rid;

        /** Check if messaging is disabled for the user */
        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor outer_accessor;
        tbb::concurrent_hash_map<std::string, bool>::const_accessor inner_accessor;

        if (isMessagingDisabled.load(std::memory_order_relaxed) ||
            (disabledConnections.find(outer_accessor, "global") &&
            outer_accessor->second.find(inner_accessor, uid)) ||
            (disabledConnections.find(outer_accessor, rid) &&
            outer_accessor->second.find(inner_accessor, uid))) {
            
            ws->send("{\"event\":\"MESSAGING_DISABLED\"}", uWS::OpCode::TEXT, true);
        } else {
            if(static_cast<int>(message.size()) > UserData::getInstance().msgSizeAllowedInBytes){
                droppedMessages.fetch_add(1, std::memory_order_relaxed);

                /** alert the client about the issue */
                ws->send("{\"event\":\"MESSAGE_SIZE_EXCEEDED\"}", uWS::OpCode::TEXT, true);

                if(webhookStatus[Webhooks::ON_MESSAGE_SIZE_EXCEEDED] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_MESSAGE_SIZE_EXCEEDED\", "
                            << "\"code\":3349, "
                            << "\"uid\":\"" << uid << "\", "
                            << "\"msg_size_allowed_in_bytes\":\"" << UserData::getInstance().msgSizeAllowedInBytes << "\"}";            
                    
                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
            }
            else if (ws->getUserData()->sendingAllowed)
            {
                if(ws->getBufferedAmount() > UserData::getInstance().maxBackpressureInBytes){
                    ws->send("{\"event\":\"YOU_ARE_RATE_LIMITED\"}", uWS::OpCode::TEXT, true);
                    droppedMessages.fetch_add(1, std::memory_order_relaxed);
                    ws->getUserData()->sendingAllowed = false;

                    if(webhookStatus[Webhooks::ON_RATE_LIMIT_EXCEEDED] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_RATE_LIMIT_EXCEEDED\", "
                                << "\"code\":3237, "
                                << "\"uid\":\"" << uid << "\"}";

                        std::string body = payload.str(); 
                        
                        sendHTTPSPOSTRequestFireAndForget(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            {}
                        );
                    }
                } else {
                    if (totalPayloadSent.load(std::memory_order_relaxed) < UserData::getInstance().maxMonthlyPayloadInBytes) {
                        unsigned int subscribers = app_->numSubscribers(rid);

                        /** Calculate cooldown duration */
                        double cooldownMillis = k * subscribers * (static_cast<double>(message.size()) / M);
                        auto cooldownDuration = std::chrono::milliseconds(static_cast<int>(cooldownMillis));

                        /** Cooldown check */
                        auto now = std::chrono::steady_clock::now();
                        if(now >= globalCooldownEnd.load(std::memory_order_relaxed)){
                            globalCooldownEnd.store(now + cooldownDuration, std::memory_order_relaxed);
                            globalMessagesSent.fetch_add(static_cast<unsigned long long>(subscribers), std::memory_order_relaxed);
                            totalPayloadSent.fetch_add(static_cast<unsigned long long>(message.size()) * static_cast<unsigned long long>(subscribers), std::memory_order_relaxed);   

                            /** Writing data to the LMDB */
                            if (ws->getUserData()->roomType == static_cast<uint8_t>(Rooms::PUBLIC_CACHE)
                            || ws->getUserData()->roomType == static_cast<uint8_t>(Rooms::PRIVATE_CACHE) 
                            || ws->getUserData()->roomType == static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) 
                            || ws->getUserData()->roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)
                            ){
                                /** write the data in the local storage */
                                write_worker(rid, uid, std::string(message));

                                /** SQL integration works in cache channels only */
                                if(featureStatus[Features::ENABLE_MYSQL_INTEGRATION] == 1){
                                    db_handler->insertSingleData(getCurrentSQLTime(), std::string(message), uid, rid);
                                }
                            }

                            /** publishing message */
                            ws->publish(rid, message, opCode, true);

                            std::for_each(::workers.begin(), ::workers.end(), [message, opCode, rid](worker_t &w) {
                                /** Check if the current thread ID matches the worker's thread ID */ 
                                if (std::this_thread::get_id() != w.thread_->get_id()) {
                                    /** Defer the message publishing to the worker's loop */ 
                                    w.loop_->defer([&w, message, opCode, rid]() {
                                        w.app_->publish(rid, message, opCode, true);
                                    });
                                }
                            });

                            /** this is a dangerous and can cause performance degrade */
                            switch(ws->getUserData()->roomType) {
                                case static_cast<uint8_t>(Rooms::PUBLIC) : {
                                    if(webhookStatus[Webhooks::ON_MESSAGE_PUBLIC_ROOM] == 1){
                                        std::ostringstream payload;
                                        payload << "{\"event\":\"ON_MESSAGE_PUBLIC_ROOM\", "
                                                << "\"code\":5017, "
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
                                    break;
                                }  

                                case static_cast<uint8_t>(Rooms::PRIVATE) : {
                                    if(webhookStatus[Webhooks::ON_MESSAGE_PRIVATE_ROOM] == 1){
                                        std::ostringstream payload;
                                        payload << "{\"event\":\"ON_MESSAGE_PRIVATE_ROOM\", "
                                                << "\"code\":5018, "
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
                                    break;
                                }

                                case static_cast<uint8_t>(Rooms::PUBLIC_STATE) : {
                                    if(webhookStatus[Webhooks::ON_MESSAGE_PUBLIC_STATE_ROOM] == 1){
                                        std::ostringstream payload;
                                        payload << "{\"event\":\"ON_MESSAGE_PUBLIC_STATE_ROOM\", "
                                                << "\"code\":5019, "
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
                                    break;
                                }

                                case static_cast<uint8_t>(Rooms::PRIVATE_STATE) : {
                                    if(webhookStatus[Webhooks::ON_MESSAGE_PRIVATE_STATE_ROOM] == 1){
                                        std::ostringstream payload;
                                        payload << "{\"event\":\"ON_MESSAGE_PRIVATE_STATE_ROOM\", "
                                                << "\"code\":5020, "
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
                                    break;
                                }

                                case static_cast<uint8_t>(Rooms::PUBLIC_CACHE) : {
                                    if(webhookStatus[Webhooks::ON_MESSAGE_PUBLIC_CACHE_ROOM] == 1){
                                        std::ostringstream payload;
                                        payload << "{\"event\":\"ON_MESSAGE_PUBLIC_CACHE_ROOM\", "
                                                << "\"code\":5021, "
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
                                    break;
                                }

                                case static_cast<uint8_t>(Rooms::PRIVATE_CACHE) : {
                                    if(webhookStatus[Webhooks::ON_MESSAGE_PRIVATE_CACHE_ROOM] == 1){
                                        std::ostringstream payload;
                                        payload << "{\"event\":\"ON_MESSAGE_PRIVATE_CACHE_ROOM\", "
                                                << "\"code\":5022, "
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
                                    break;
                                }

                                case static_cast<uint8_t>(Rooms::PUBLIC_STATE_CACHE) : {
                                    if(webhookStatus[Webhooks::ON_MESSAGE_PUBLIC_STATE_CACHE_ROOM] == 1){
                                        std::ostringstream payload;
                                        payload << "{\"event\":\"ON_MESSAGE_PUBLIC_STATE_CACHE_ROOM\", "
                                                << "\"code\":5023, "
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
                                    break;
                                }

                                case static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE) : {
                                    if(webhookStatus[Webhooks::ON_MESSAGE_PRIVATE_STATE_CACHE_ROOM] == 1){
                                        std::ostringstream payload;
                                        payload << "{\"event\":\"ON_MESSAGE_PRIVATE_STATE_CACHE_ROOM\", "
                                                << "\"code\":5024, "
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
                                    break;
                                }
                            }
                        }
                        else
                        {
                            droppedMessages.fetch_add(1, std::memory_order_relaxed);
                            ws->send("{\"event\":\"YOU_ARE_RATE_LIMITED\"}", uWS::OpCode::TEXT, true);
                        }
                    } else {
                        droppedMessages.fetch_add(1, std::memory_order_relaxed);
                        ws->send("{\"event\":\"MONTHLY_DATA_TRANSFER_LIMIT_EXHAUSTED\"}", uWS::OpCode::TEXT, true);

                        if(webhookStatus[Webhooks::ON_MONTHLY_DATA_TRANSFER_LIMIT_EXHAUSTED] == 1){
                            std::ostringstream payload;
                            payload << "{\"event\":\"ON_MONTHLY_DATA_TRANSFER_LIMIT_EXHAUSTED\", "
                                    << "\"code\":3758, "
                                    << "\"uid\":\"" << uid << "\", "
                                    << "\"rid\":\"" << rid << "\", "
                                    << "\"max_monthly_payload_in_bytes\":\"" << UserData::getInstance().maxMonthlyPayloadInBytes << "\"}";              
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
            } else {
                ws->send("{\"event\":\"YOU_ARE_RATE_LIMITED\"}", uWS::OpCode::TEXT, true);
                droppedMessages.fetch_add(1, std::memory_order_relaxed);

                if(webhookStatus[Webhooks::ON_RATE_LIMIT_EXCEEDED] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_RATE_LIMIT_EXCEEDED\", "
                            << "\"code\":3237, "
                            << "\"uid\":\"" << uid << "\"}";

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
    },
    .dropped = [](auto *ws, std::string_view message, uWS::OpCode /*opCode*/) {
        droppedMessages.fetch_add(1, std::memory_order_relaxed);

        if(webhookStatus[Webhooks::ON_MESSAGE_DROPPED] == 1){
            std::ostringstream payload;
            payload << "{\"event\":\"ON_MESSAGE_DROPPED\", "
                    << "\"code\":6002, "
                    << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                    << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                    << "\"message\":\"" << message << "\"}";          

            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        }
    },
    .drain = [](auto *ws) {
        if(ws->getBufferedAmount() < (UserData::getInstance().maxBackpressureInBytes / 2)){
            ws->getUserData()->sendingAllowed = true;
            ws->send("{\"event\":\"RATE_LIMIT_LIFTED\"}", uWS::OpCode::TEXT, true);

            if(webhookStatus[Webhooks::ON_RATE_LIMIT_LIFTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_RATE_LIMIT_LIFTED\", "
                        << "\"code\":6001, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            }
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

        /** Thread-safe removal from connections map */
        {
            tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
            if (connections.find(conn_accessor, userId)) {
                connections.erase(conn_accessor);  // Correct usage
            }
        }

        /** Decrement global connection counter */
        globalConnectionCounter.fetch_sub(1, std::memory_order_relaxed);

        /** Thread-safe removal from uid map */
        {
            tbb::concurrent_hash_map<std::string, bool>::accessor uid_accessor;
            if (uid.find(uid_accessor, userId)) {
                uid.erase(uid_accessor);  // Correct usage
            }
        }

        /** Manually unsubscribing */
        ws->unsubscribe(userId);
        ws->unsubscribe(BROADCAST);

        /** Close connection */
        closeConnection(ws, this);
    }
    }).get("/api/v1/metrics", [](auto *res, auto *req) {
        /** fetch all the server metrics */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });
         
        if(UserData::getInstance().clientApiKey.empty()){
            fetchAndPopulateUserData();
        }

        if (req->getHeader("api-key") != UserData::getInstance().adminApiKey) {
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("401 Unauthorized");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
                });
            }

            return;
        }

        if(!*isAborted){
            res->cork([res]() {
                res->writeStatus("200 OK");
                res->writeHeader("Content-Type", "application/json");
                res->end(R"({"connections": )" 
                + std::to_string(globalConnectionCounter.load(std::memory_order_relaxed)) 
                + R"(,"messages_sent": )" 
                + std::to_string(globalMessagesSent.load(std::memory_order_relaxed)) 
                + R"(,"average_payload_size": )" 
                + std::to_string(averagePayloadSize.load(std::memory_order_relaxed)) 
                + R"(,"total_payload_sent": )" 
                + std::to_string(totalPayloadSent.load(std::memory_order_relaxed)) 
                + R"(,"total_rejected_requests": )" 
                + std::to_string(totalRejectedRquests.load(std::memory_order_relaxed))
                + R"(,"average_latency": )" 
                + std::to_string(averageLatency.load(std::memory_order_relaxed)) 
                + R"(,"dropped_messages": )" 
                + std::to_string(droppedMessages.load(std::memory_order_relaxed)) 
                + R"(})");
            });
        }
	}).post("/api/v1/invalidate", [](auto *res, auto *req) {
        /** update the metadata used by the server */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        if(UserData::getInstance().adminApiKey.empty()){
            fetchAndPopulateUserData();
        }

        std::string_view apiKey = req->getHeader("api-key");
        std::string_view secret = req->getHeader("secret");

        /** check if the API key is valid or not */
        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
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
                        totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

                        if(!*isAborted){
                            res->cork([res]() {
                                res->writeStatus("403");
                                res->writeHeader("Content-Type", "application/json");
                                res->end(R"({"error": "Unauthorized access. Invalid signature!"})");
                            });
                        }

                        return;
                    }

                    /** Parse the JSON response */ 
                    int needsDBUpdate = populateUserData(body);
                    
                    if(needsDBUpdate == 1){
                        /** check if the connection parameters are changed */
                        std::for_each(::workers.begin(), ::workers.end(), [](worker_t &w) {
                            /** Defer the message publishing to the worker's loop */ 
                            w.loop_->defer([&w]() {
                                w.db_handler->manualCreateConnection();
                            });
                        });
                    } else if(needsDBUpdate == -1) {
                        std::for_each(::workers.begin(), ::workers.end(), [](worker_t &w) {
                            /** Defer the message publishing to the worker's loop */ 
                            w.loop_->defer([&w]() {
                                w.db_handler->flushRemainingData();
                                w.db_handler->disconnect();
                            });
                        });
                    }

                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("200 OK");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Metadata invalidated successfully."})");
                        });
                    }
                } catch (std::exception &e) {
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Invalid JSON format!"})");
                        });
                    }
                }
            }
        });
	}).post("/api/v1/mysql/sync", [](auto *res, auto *req) {
        /** sync all the data in the buffers to integrated mysql server */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        if(featureStatus[Features::ENABLE_MYSQL_INTEGRATION] == 0){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "MySQL integration is disabled!"})");
                });
            }

            return;
        }

        if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
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
            res->cork([res]() {
                res->writeStatus("200 OK");
                res->writeHeader("Content-Type", "application/json");
                res->end(R"({"message": "MySQL data synced successfully."})");
            });
        }
	}).get("/api/v1/rooms", [this](auto *res, auto *req) {
        /** fetch all the rooms present on the server */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403 Forbidden");
                    res->writeHeader("Content-Type", "application/json");
                    res->end("{\"error\": \"Unauthorized access. Invalid API key!\"}");
                });
            }

            return;
        }

        nlohmann::json data = nlohmann::json::array(); 

        for (const auto& [rid, users] : topics) {  
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
        
        if(!*isAborted){
            res->cork([res, data]() {
                res->writeStatus("200 OK");
                res->writeHeader("Content-Type", "application/json");
                res->end(data.dump());  
            });
        }
	}).post("/api/v1/rooms/connections", [this](auto *res, auto *req) {
        /** get all the connectiond for a room */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403 Forbidden");
                    res->writeHeader("Content-Type", "application/json");
                    res->end("{\"error\": \"Unauthorized access. Invalid API key!\"}");
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

                        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor outer_accessor;

                        if (topics.find(outer_accessor, rid)) {
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

                        data.push_back(roomData);
                    }

                    if(!*isAborted){
                        res->cork([res, data]() {
                            res->writeStatus("200 OK");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(data.dump()); 
                        });
                    }
                } catch (std::exception &e) {
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Invalid JSON format!"})");
                        });
                    }
                }
            }
        }); 
	}).post("/api/v1/connections/update/room", [this](auto *res, auto *req) {
        auto isAborted = std::make_shared<bool>(false);
        res->onAborted([isAborted]() { *isAborted = true; });

        if (req->getHeader("api-key") != UserData::getInstance().clientApiKey) {
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            if (!res->hasResponded()) {
                res->cork([res]() {
                    res->writeStatus("403 Forbidden");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!", "code": 3203})");
                });
            }
            return;
        }

        std::string body;
        body.reserve(1024);

        res->onData([res, isAborted, body = std::move(body)](std::string_view data, bool last) mutable {
            body.append(data);
            if (!last) return;

            try {
                auto parsedJson = nlohmann::json::parse(body);
                std::string rid = parsedJson["rid"];
                std::string uid = parsedJson["uid"];

                if (rid.empty() || rid.length() > 160) {
                    totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
                    if (!res->hasResponded()) {
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "The room id length should be between 1 to 160 characters!", "code": 3484})");
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
                    totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
                    
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end("{\"error\": \"The provided room type is invalid!\", \"code\": 3925}");
                        });
                    }

                    return;
                }

                tbb::concurrent_hash_map<std::string, WebSocketData>::const_accessor accessor;
                if (!connections.find(accessor, uid)) {
                    totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
                    if (!res->hasResponded()) {
                        res->cork([res]() {
                            res->writeStatus("404 Not Found");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Connection not found!", "code": 3910})");
                        });
                    }
                    return;
                }

                auto *ws = accessor->second.ws;
                auto *worker = accessor->second.worker;

                if (ws->getUserData()->rid == rid) {
                    totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
                    if (!res->hasResponded()) {
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "You are already in the same room!", "code": 3780})");
                        });
                    }
                    return;
                }

                tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::const_accessor outer_accessor;
                if (bannedConnections.find(outer_accessor, rid) && outer_accessor->second.count(uid)) {
                    totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
                    if (!res->hasResponded()) {
                        res->cork([res]() {
                            res->writeStatus("403 Forbidden");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "You have been banned from this room!", "code": 3371})");
                        });
                    }
                    return;
                }

                if(roomType == static_cast<uint8_t>(Rooms::PRIVATE) 
                || roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE) 
                || roomType == static_cast<uint8_t>(Rooms::PRIVATE_CACHE) 
                || roomType == static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE)
                ){
                    if(webhookStatus[Webhooks::ON_VERIFICATION_REQUEST] == 1){
                        std::ostringstream payload;

                        switch (roomType)
                        {
                            case static_cast<uint8_t>(Rooms::PRIVATE) : {
                                payload << "{\"event\":\"ON_VERIFICATION_REQUEST\", "
                                << "\"trigger\":\"INIT_PRIVATE_ROOM_VERIFICATION\", "
                                << "\"code\":4001, "
                                << "\"uid\":\"" << uid << "\", "
                                << "\"rid\":\"" << rid << "\"}";
                                break;
                            }

                            case static_cast<uint8_t>(Rooms::PRIVATE_STATE) : {
                                payload << "{\"event\":\"ON_VERIFICATION_REQUEST\", "
                                << "\"trigger\":\"INIT_PRIVATE_STATE_ROOM_VERIFICATION\", "
                                << "\"code\":4002, "
                                << "\"uid\":\"" << uid << "\", "
                                << "\"rid\":\"" << rid << "\"}";
                                break;
                            }

                            case static_cast<uint8_t>(Rooms::PRIVATE_CACHE) : {
                                payload << "{\"event\":\"ON_VERIFICATION_REQUEST\", "
                                << "\"trigger\":\"INIT_PRIVATE_CACHE_ROOM_VERIFICATION\", "
                                << "\"code\":4003, "
                                << "\"uid\":\"" << uid << "\", "
                                << "\"rid\":\"" << rid << "\"}";
                                break;
                            }

                            case static_cast<uint8_t>(Rooms::PRIVATE_STATE_CACHE) : {
                                payload << "{\"event\":\"ON_VERIFICATION_REQUEST\", "
                                << "\"trigger\":\"INIT_PRIVATE_STATE_CACHE_ROOM_VERIFICATION\", "
                                << "\"code\":4004, "
                                << "\"uid\":\"" << uid << "\", "
                                << "\"rid\":\"" << rid << "\"}";
                                break;
                            }
                        }

                        std::string body = payload.str(); 
                        httplib::Headers headers = {};

                        /** if the webhook secret is present add the hmac */
                        if(UserData::getInstance().webhookSecret.length() > 0){
                            unsigned char hmac_result[HMAC_SHA256_DIGEST_LENGTH];  /**< Buffer to store the HMAC result */
                            hmac_sha256(SECRET, strlen(SECRET), body.c_str(), body.length(), hmac_result);  /**< Compute HMAC */
                            headers = {{"X-HMAC-Signature", to_hex(hmac_result, HMAC_SHA256_DIGEST_LENGTH)}}; 
                        }
        
                        int status = sendHTTPSPOSTRequest(
                            UserData::getInstance().webHookBaseUrl,
                            UserData::getInstance().webhookPath,
                            body,
                            headers
                        ).status;

                        if(status != 200){
                            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
                            
                            if(!*isAborted){
                                res->cork([res]() {
                                    res->writeStatus("403 Forbidden");
                                    res->writeHeader("Content-Type", "application/json");
                                    res->end("{\"error\": \"You are not allowed to access this private room!\", \"code\": 3511}");
                                });
                            }

                            return;
                        }
                    } else {
                        totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

                        if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                            std::ostringstream payload;
                            payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                                    << "\"trigger\":\"ON_VERIFICATION_REQUEST_WEBHOOK_DISABLED\", "  
                                    << "\"code\":3376, "
                                    << "\"uid\":\"" << uid << "\", "
                                    << "\"rid\":\"" << rid << "\", "
                                    << "\"message\":\"Please enable ON_VERIFICATION_REQUEST webhook to use private rooms!\"}";

                            std::string body = payload.str(); 
                            
                            sendHTTPSPOSTRequestFireAndForget(
                                UserData::getInstance().webHookBaseUrl,
                                UserData::getInstance().webhookPath,
                                body,
                                {}
                            );
                        }

                        if(!*isAborted){
                            res->cork([res]() {
                                res->writeStatus("403 Forbidden");
                                res->writeHeader("Content-Type", "application/json");
                                res->end("{\"error\": \"You are not allowed to access this private room!\", \"code\": 3511}");
                            });
                        }

                        return;
                    } 
                }

                closeConnection(ws, worker);
                ws->getUserData()->rid = rid;
                ws->getUserData()->roomType = roomType;
                openConnection(ws, worker);

                if (!res->hasResponded()) {
                    res->cork([res]() {
                        res->writeStatus("200 OK");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"message": "Successfully updated the room for the uid!", "code": 7481})");
                    });
                }
            } catch (const std::exception &e) {
                if (!res->hasResponded()) {
                    res->cork([res, e]() {
                        res->writeStatus("400 Bad Request");
                        res->writeHeader("Content-Type", "application/json");
                        res->end("{\"error\": \"Invalid JSON format: " + std::string(e.what()) + "\", \"code\": 8931}");
                    });
                }
            }
        });
	}).post("/api/v1/broadcast", [this](auto *res, auto *req) {
        /** broadcast a message to everyone connected to the server */
        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key."})");
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

                    /** broadcast a message to all the rooms */
                    std::for_each(::workers.begin(), ::workers.end(), [message](worker_t &w) {
                        /** Defer the message publishing to the worker's loop */ 
                        w.loop_->defer([&w, message]() {
                            w.app_->publish(BROADCAST, message, uWS::OpCode::TEXT, true);
                        });
                    });

                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("200 OK");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Successfully broadcasted the message to everyone on the server!"})");
                        });
                    }
                } catch (std::exception &e) {
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Invalid JSON format!"})");
                        });
                    }
                }
            }
        });
	}).post("/api/v1/rooms/broadcast", [this](auto *res, auto *req) {
        /** broadcast a message to a particular room */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
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
                        /** broadcast a message to a specific room */
                        std::for_each(::workers.begin(), ::workers.end(), [message, rid](worker_t &w) {
                            /** Defer the message publishing to the worker's loop */ 
                            w.loop_->defer([&w, message, rid]() {
                                w.app_->publish(rid, message, uWS::OpCode::TEXT, true);
                            });
                        });
                    }

                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("200 OK");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Successfully broadcasted the message to the given room!"})");
                        });
                    }
                } catch (std::exception &e) {
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Invalid JSON format."})");
                        });
                    }
                }
            }
        });
	}).post("/api/v1/connections/broadcast", [this](auto *res, auto *req) {
        /** broadcast a message to a particular connection */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key."})");
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
                        /** broadcast a message to a specific member of a room */
                        std::for_each(::workers.begin(), ::workers.end(), [message, uid](worker_t &w) {
                            /** Defer the message publishing to the worker's loop */ 
                            w.loop_->defer([&w, message, uid]() {
                                w.app_->publish(uid, message, uWS::OpCode::TEXT, true);
                            });
                        });
                    }

                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("200 OK");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Successfully broadcasted the message to the given connection!"})");
                        });
                    }
                } catch (std::exception &e) {
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Invalid JSON format!"})");
                        });
                    }
                }
            }
        });
	}).post("/api/v1/rooms/ban", [this](auto *res, auto *req) {
        /** ban all the users in a room and prevent them from connecting again (it will disconnect the user from the server) */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key."})");
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

                    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor global_accessor;
                    tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                    /** saving all the banned connections in a map */

                    for (const auto& item : parsedJson) {
                        /** Extract `rid` and `uid` from each item in the request */ 
                        std::string rid = item["rid"];
                        std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                        /** Try to find or insert the outer map entry */
                        if (!bannedConnections.find(global_accessor, rid)) {
                            bannedConnections.insert(global_accessor, rid);
                        }

                        for (const auto& uid : uids) {                            
                            /** Check if uid already exists before inserting */
                            if (!global_accessor->second.find(user_accessor, uid)) {
                                global_accessor->second.insert(user_accessor, uid);
                                user_accessor->second = true;

                                /** Fetch the connection for the given uid from the connections map */
                                tbb::concurrent_hash_map<std::string, WebSocketData>::accessor conn_accessor;
                                if (connections.find(conn_accessor, uid)) {
                                    uWS::WebSocket<true, true, PerSocketData>* ws = conn_accessor->second.ws; 
                                    worker_t* worker = conn_accessor->second.worker; 

                                    /** Disconnect the WebSocket or perform any other disconnection logic */
                                    worker->loop_->defer([ws]() {
                                        ws->end(1008, "{\"event\":\"YOU_HAVE_BEEN_BANNED\"}");
                                    });
                                }
                            }
                        }
                    }

                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("200 OK");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Given members are successfully banned from the given rooms!"})");
                        });
                    }
                } catch (std::exception &e) {
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Invalid JSON format!"})");
                        });
                    }
                }
            }
        });
	}).post("/api/v1/rooms/unban", [this](auto *res, auto *req) {
        /** ban all the users in a room and prevent them from connecting again (it will disconnect the user from the server) */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
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
                    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor global_accessor;
                    tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                    for (const auto& item : parsedJson) {
                        /** Extract `rid` and `uid` from each item in the request */ 
                        std::string rid = item["rid"];
                        std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                        /** Check if the room exists before trying to erase */
                        if (bannedConnections.find(global_accessor, rid)) {
                            for (const auto& uid : uids) {
                                /** Check if the user exists before erasing */
                                if (global_accessor->second.find(user_accessor, uid)) {
                                    global_accessor->second.erase(user_accessor);
                                }
                            }

                            /** If the inner map becomes empty, erase the entire entry */
                            if (global_accessor->second.empty()) {
                                bannedConnections.erase(global_accessor);
                            }
                        }
                    }

                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("200 OK");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"message": "Members are successfully unbanned from the given rooms!"})");
                        });
                    }
                } catch (std::exception &e) {
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Invalid JSON format!"})");
                        });
                    }
                }
            }
        });
	}).put("/api/v1/server/messaging/:action", [this](auto *res, auto *req) {
        /** enable or disable message sending at the server level (for everyone) */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view apiKey = req->getHeader("api-key");
        std::string_view action = req->getParameter("action");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
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
                res->cork([res]() {
                    res->writeStatus("400 Bad Request");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Invalid action!"})");
                });
            }
            return;
        }

        if(!*isAborted){
            res->cork([res, action]() {
                res->writeStatus("200 OK");
                res->writeHeader("Content-Type", "application/json");

                if(action == "enable")
                    res->end(R"({"message": "Messaging successfully enabled for everyone!"})");
                else
                    res->end(R"({"message": "Messaging successfully disabled for everyone!"})");
            });
        }
	}).post("/api/v1/rooms/messaging/:action", [this](auto *res, auto *req) {
        /** enable or disable messaging at room level */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view apiKey = req->getHeader("api-key");
        std::string_view action = req->getParameter("action");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
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
                    tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor global_accessor;
                    tbb::concurrent_hash_map<std::string, bool>::accessor user_accessor;

                    for (const auto& item : parsedJson) {
                        /** Extract `rid` and `uid` from each item in the request */ 
                        std::string rid = item["rid"];
                        std::vector<std::string> uids = item["uid"].get<std::vector<std::string>>();

                        if (action == "enable")
                        {
                            /** Check if the room exists before trying to erase */
                            if (disabledConnections.find(global_accessor, rid)) {
                                for (const auto& uid : uids) {
                                    /** Check if the user exists before erasing */
                                    if (global_accessor->second.find(user_accessor, uid)) {
                                        global_accessor->second.erase(user_accessor);
                                    }
                                }

                                /** If the inner map becomes empty, erase the entire entry */
                                if (global_accessor->second.empty()) {
                                    disabledConnections.erase(global_accessor);
                                }
                            }
                        }
                        else if (action == "disable")
                        {
                            /** Try to find or insert the outer map entry */
                            if (!disabledConnections.find(global_accessor, rid)) {
                                disabledConnections.insert(global_accessor, rid);
                            }

                            for (const auto& uid : uids) {                            
                                /** Check if uid already exists before inserting */
                                if (!global_accessor->second.find(user_accessor, uid)) {
                                    global_accessor->second.insert(user_accessor, uid);
                                    user_accessor->second = true;
                                }
                            }
                        }
                        else
                        {
                            if(!*isAborted){
                                res->cork([res]() {
                                    res->writeStatus("400 Bad Request");
                                    res->writeHeader("Content-Type", "application/json");
                                    res->end(R"({"error": "Invalid action!"})");
                                });
                            }

                            return;
                        }
                    }

                    if(!*isAborted){
                        res->cork([res, action]() {
                            res->writeStatus("200 OK");
                            res->writeHeader("Content-Type", "application/json");

                            if(action == "enable")
                                res->end(R"({"message": "Messaging successfully enabled for the members of the given rooms!"})");
                            else
                                res->end(R"({"message": "Messaging successfully disabled for the members of the given rooms!"})");
                        });
                    }
                } catch (std::exception &e) {
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Invalid JSON format!"})");
                        });
                    }
                }
            }
        });
	}).get("/api/v1/connections/banned", [this](auto *res, auto *req) {
        /** Handle the request to fetch all banned connections */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view apiKey = req->getHeader("api-key");

        /** Check if the API key is valid */
        if (apiKey != UserData::getInstance().adminApiKey) {
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            /** Respond with 403 Unauthorized if the API key is invalid */
            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
                });
            }

            return;
        }

        /** Create and reserve space for the JSON response */
        nlohmann::json data = nlohmann::json::array(); 

        for (const auto& [rid, users] : bannedConnections) {  
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

        /** Send the successful response with all banned connections */
        if(!*isAborted){
            res->cork([res, data]() {
                res->writeStatus("200 OK");
                res->writeHeader("Content-Type", "application/json");
                res->end(data.dump());  /** Serialize the JSON response and send it */ 
            });
        }
	}).get("/api/v1/connections/messaging/disabled", [this](auto *res, auto *req) {
        /** Handle the request to fetch all disabled connections */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view apiKey = req->getHeader("api-key");

        /** Check if the API key is valid */
        if (apiKey != UserData::getInstance().adminApiKey) {
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            /** Respond with 403 Unauthorized if the API key is invalid */
            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
                });
            }

            return;
        }

        /** Create and reserve space for the JSON response */
        nlohmann::json json_response = nlohmann::json::array();

        for (const auto& [rid, users] : disabledConnections) {  
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
        
        /** Send the successful response with all banned connections */
        if(!*isAborted){
            res->cork([res, json_response]() {
                res->writeStatus("200 OK");
                res->writeHeader("Content-Type", "application/json");
                res->end(json_response.dump());  /** Serialize the JSON response and send it */ 
            });
        }
	}).get("/api/v1/messages/room/:rid", [this](auto *res, auto *req) {
        /** retrieve the messages for cache rooms (for other rooms no data will be returned) */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        std::string_view rid = req->getParameter("rid");
        std::string_view apiKey = req->getHeader("api-key");
        std::string_view uid = req->getHeader("uid");

        tbb::concurrent_hash_map<std::string, tbb::concurrent_hash_map<std::string, bool>>::accessor outer_accessor;

        if (topics.find(outer_accessor, std::string(rid))) {
            /** Access the inner map corresponding to 'rid' */
            tbb::concurrent_hash_map<std::string, bool>& inner_map = outer_accessor->second;

            /** Create an accessor for the inner map */
            tbb::concurrent_hash_map<std::string, bool>::accessor inner_accessor;

            /** Check if value exists in the inner map (uid) */
            if (inner_map.find(inner_accessor, std::string(uid))) {
                int limit, offset;

                try {
                    limit = std::stoi(req->getQuery("limit").empty() ? "10" : std::string(req->getQuery("limit")));
                } catch (const std::exception& e) {
                    limit = 10; /** Default value if conversion fails */
                }

                if (limit > 10) {
                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("400 Bad Request");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Limit cannot be greater than 10!"})");
                        });
                    }

                    return;
                }

                try {
                    offset = std::stoi(req->getQuery("offset").empty() ? "0" : std::string(req->getQuery("offset")));
                } catch (const std::exception& e) {
                    offset = 0; /** Default value if conversion fails */
                }

                write_worker(std::string(rid), "", "", true);

                if (apiKey != UserData::getInstance().clientApiKey) {
                    totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

                    if(!*isAborted){
                        res->cork([res]() {
                            res->writeStatus("403");
                            res->writeHeader("Content-Type", "application/json");
                            res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
                        });
                    }

                    return;
                }

                if(!*isAborted){
                    res->cork([res, rid, limit, offset]() {
                        res->writeStatus("200 OK");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(read_worker(std::string(rid), limit, offset));
                    });
                }
            } else {
                if(!*isAborted){
                    res->cork([res]() {
                        res->writeStatus("403 Forbidden");
                        res->writeHeader("Content-Type", "application/json");
                        res->end(R"({"error": "Access denied!"})");
                    });
                }
            }
        } else {
            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403 Forbidden");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Access denied!"})");
                });
            }
        }
	}).del("/api/v1/database", [this](auto *res, auto *req) {
        /** delete all the data present in the LMDB database */

        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        /** Extract the API key from the request header */
        std::string_view apiKey = req->getHeader("api-key");

        /** Check if the provided API key is valid */
        if (apiKey != UserData::getInstance().adminApiKey) {
            /** Increment the rejected request counter to track unauthorized access */
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

            /** Respond with 403 Forbidden if the API key is invalid */
            if(!*isAborted){
                res->cork([res]() {
                    res->writeStatus("403");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Unauthorized access. Invalid API key!"})");
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
                res->cork([res, e]() {
                    res->writeStatus("500 Internal Server Error");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": ")" + std::string(e.what()) + R"("})");
                });
            }
        }
	}).get("/api/v1/ping", [](auto *res, auto */*req*/) {
        /** send pong as a response for ping */
        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        if(!*isAborted){
            res->cork([res]() {
                res->writeStatus("200 OK");
                res->end("pong!");
            });
        }
	}).any("/*", [](auto *res, auto */*req*/) {
        /** wildcard url to handle any random request */
        auto isAborted = std::make_shared<bool>(false);

        res->onAborted([isAborted]() {
            /** connection aborted */
            *isAborted = true;
        });

        totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);

        if(!*isAborted){
            res->cork([res]() {
                res->writeStatus("404 Not Found");
                res->writeHeader("Content-Type", "application/json");
                res->end(R"({"error": "The requested resource is not found!"})");
            });
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
    std::string certPath = "/etc/letsencrypt/live/" + std::string(domain) + "/cert.pem";
    
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
    std::string checkCmd = "openssl x509 -checkend 86400 -noout -in /etc/letsencrypt/live/" + std::string(domain) + "/cert.pem";

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
    std::string createCmd = "certbot certonly --standalone --staging --non-interactive --agree-tos "
    "--email adisingh925@gmail.com --key-type ecdsa -d " + std::string(domain) + 
    " --config-dir /home/socketlink/certbot-config "
    "--work-dir /home/socketlink/certbot-work "
    "--logs-dir /home/socketlink/certbot-logs";
    std::system(createCmd.c_str());

    std::ofstream hookFile("/etc/letsencrypt/renewal-hooks/deploy/restart-socketlink.sh");
    if (hookFile) {
        hookFile << "#!/bin/bash\n";
        hookFile << "echo \"SSL certificate renewed. Restarting socketlink-client-backend.service...\"\n";
        hookFile << "systemctl restart socketlink-client-backend.service\n";
        hookFile << "echo \"Server restarted successfully.\"\n";
        hookFile.close();

        /** Make the script executable */ 
        std::string chmodCmd = "chmod +x /etc/letsencrypt/renewal-hooks/deploy/restart-socketlink.sh";
        std::system(chmodCmd.c_str());
        std::cout << "Deploy hook created successfully!\n";
    } else {
        std::cerr << "Failed to create deploy hook!\n";
    }
}

/**
 * Renews the SSL certificate for the domain if necessary.
 *
 * @param domain The domain name.
 */
void renewCertificate(std::string_view domain) {
    std::cout << "Renewing SSL certificate for " << domain << "...\n";
    std::string renewCmd = "certbot renew --quiet --non-interactive --preferred-challenges http";
    std::system(renewCmd.c_str());
}

/* Main */
int main() {
    /** Fetch and populated data before starting the threads */
    fetchAndPopulateUserData();
    init_env();

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

    workers.resize(std::thread::hardware_concurrency());
    
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