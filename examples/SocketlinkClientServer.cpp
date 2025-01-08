/* We simply call the root header file "App.h", giving you uWS::App and uWS::SSLApp */
#include "App.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include "json.hpp"
#include <thread>
#include <vector>
#include <memory>
#include <iostream>
#include <fstream>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>
#include <lmdb.h>
#include <chrono>

/**
 * database
 */

/** Global variables */ 
MDB_env* env;
std::mutex write_mutex;

/** Initialize LMDB environment */ 
void init_env() {
    if (mdb_env_create(&env) != 0) {
        std::cerr << "Failed to create LMDB environment.\n";
        exit(-1);
    }

    if (mdb_env_set_mapsize(env, 10485760) != 0) { 
        std::cerr << "Failed to set map size.\n";
        exit(-1);
    }

    if (mdb_env_set_maxreaders(env, 16) != 0) {
        std::cerr << "Failed to set max readers.\n";
        exit(-1);
    }

    if (mdb_env_set_maxdbs(env, 10) != 0) {
        std::cerr << "Failed to set max databases.\n";
        exit(-1);
    }

    if (mdb_env_open(env, "./messages_db", 0, 0664) != 0) {
        std::cerr << "Failed to open LMDB environment.\n";
        exit(-1);
    }

    std::cout << "Environment initialized successfully.\n";
}

/**
 * Internal Constants
 */
constexpr const char* INTERNAL_IP = "169.254.169.254";
constexpr const char* MASTER_SERVER_URL = "master.socketlink.io";
constexpr const char* SECRET = "406$%&88767512673QWEdsf379254196073524";
constexpr const int PORT = 9001;

/** 
 * Sending Constants
 */
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
constexpr const char* BROADCAST = "BROADCAST";
constexpr const char* YOU_HAVE_BEEN_BANNED = "YOU_HAVE_BEEN_BANNED";

/**
 * webhooks
 */
enum class Webhooks : uint32_t
{
    /** Connection-related events */
    ON_CONNECTION_UPGRADE_REJECTED = 1 << 0,            // 1 (binary 00000001)

    /** Message-related events */
    ON_MESSAGE_PUBLIC_ROOM = 1 << 1,                    // 2 (binary 00000010)
    ON_MESSAGE_PRIVATE_ROOM = 1 << 2,                   // 4 (binary 00000100)
    ON_MESSAGE_PRIVATE_STATE_ROOM = 1 << 3,             // 8 (binary 00001000)
    ON_MESSAGE_PUBLIC_STATE_ROOM = 1 << 4,              // 16 (binary 00010000)

    /** Common webhooks */
    ON_RATE_LIMIT_EXCEEDED = 1 << 5,                    // 32 (binary 00100000)
    ON_RATE_LIMIT_LIFTED = 1 << 6,                      // 64 (binary 01000000)
    ON_MESSAGE_DROPPED = 1 << 7,                        // 128 (binary 10000000)
    ON_DAILY_MESSAGE_LIMIT_EXHAUSTED = 1 << 8,          // 256 (binary 100000000)
    ON_MESSAGE_SIZE_EXCEEDED = 1 << 9,                  // 512 (binary 1000000000)
    ON_MAX_CONNECTION_LIMIT_REACHED = 1 << 10,          // 1024 (binary 10000000000)
    ON_VERIFICATION_REQUEST = 1 << 11,                  // 2048 (binary 100000000000)

    /** Connection open events */
    ON_CONNECTION_OPEN_PUBLIC_ROOM = 1 << 12,           // 4096 (binary 10000000000000)
    ON_CONNECTION_OPEN_PRIVATE_ROOM = 1 << 13,          // 8192 (binary 100000000000000)
    ON_CONNECTION_OPEN_PRIVATE_STATE_ROOM = 1 << 14,    // 16384 (binary 1000000000000000)
    ON_CONNECTION_OPEN_PUBLIC_STATE_ROOM = 1 << 15,     // 32768 (binary 10000000000000000)

    /** Connection close events */
    ON_CONNECTION_CLOSE_PUBLIC_ROOM = 1 << 16,          // 65536 (binary 100000000000000000)
    ON_CONNECTION_CLOSE_PRIVATE_ROOM = 1 << 17,         // 131072 (binary 1000000000000000000)
    ON_CONNECTION_CLOSE_PRIVATE_STATE_ROOM = 1 << 18,   // 262144 (binary 10000000000000000000)
    ON_CONNECTION_CLOSE_PUBLIC_STATE_ROOM = 1 << 19,    // 524288 (binary 100000000000000000000)

    /** Room occupied events */
    ON_ROOM_OCCUPIED_PUBLIC_ROOM = 1 << 20,             // 1048576 (binary 1000000000000000000000)
    ON_ROOM_OCCUPIED_PRIVATE_ROOM = 1 << 21,            // 2097152 (binary 10000000000000000000000)
    ON_ROOM_OCCUPIED_PRIVATE_STATE_ROOM = 1 << 22,      // 4194304 (binary 100000000000000000000000)
    ON_ROOM_OCCUPIED_PUBLIC_STATE_ROOM = 1 << 23,       // 8388608 (binary 1000000000000000000000000)

    /** Room vacated events */
    ON_ROOM_VACATED_PUBLIC_ROOM = 1 << 24,              // 16777216 (binary 10000000000000000000000000)
    ON_ROOM_VACATED_PRIVATE_ROOM = 1 << 25,             // 33554432 (binary 100000000000000000000000000)
    ON_ROOM_VACATED_PRIVATE_STATE_ROOM = 1 << 26,       // 67108864 (binary 1000000000000000000000000000)
    ON_ROOM_VACATED_PUBLIC_STATE_ROOM = 1 << 27         // 134217728 (binary 10000000000000000000000000000)
};

constexpr uint8_t PUBLIC_ROOM = 0;
constexpr uint8_t PRIVATE_ROOM = 1;
constexpr uint8_t PUBLIC_STATE_ROOM = 2;
constexpr uint8_t PRIVATE_STATE_ROOM = 3;

struct HTTPResponse {
    std::string body;
    int status;
};

/**
 * uWebSocket worker runs in a separate thread
 */
struct worker_t
{
  void work();
  
  /* uWebSocket worker listens on separate port, or share the same port (works on Linux). */
  struct us_listen_socket_t *listen_socket_;

  /* Every thread has its own Loop, and uWS::Loop::get() returns the Loop for current thread.*/
  struct uWS::Loop *loop_;

  /* Need to capture the uWS::App object (instance). */
  std::shared_ptr<uWS::App> app_;

  /* Thread object for uWebSocket worker */
  std::shared_ptr<std::thread> thread_;
};

/* uWebSocket workers. */
std::vector<worker_t> workers;

std::atomic<int> globalConnectionCounter(0);
std::atomic<unsigned long long> globalMessagesSent{0}; 
std::atomic<unsigned long long> totalPayloadSent{0};
std::atomic<unsigned long long> totalRejectedRquests{0};
std::atomic<double> averagePayloadSize{0.0};
std::atomic<double> averageLatency{0.0};
std::atomic<unsigned long long> droppedMessages{0};
std::unordered_map<std::string, std::set<std::string>> topics;
std::unordered_set<std::string> bannedConnections;
std::unordered_map<Webhooks, int> webhookStatus;
std::unordered_set<std::string> uid;

class UserData {
private:
    /** Private constructor to prevent instantiation */ 
    UserData() = default;

public:
    int duration;
    int msg_per_day;
    int msg_per_second_per_connection;
    int msg_size_allowed_in_bytes;
    int connections;
    std::string clientApiKey;
    std::string adminApiKey;
    std::string webHookBaseUrl;
    std::string webhookPath;
    std::string webhookSecret;
    uint32_t webhooks;

    /** Public static method to get the single instance */ 
    static UserData& getInstance() {
        static UserData instance;
        return instance;
    }

    /** Delete copy constructor and assignment operator */ 
    UserData(const UserData&) = delete;
    UserData& operator=(const UserData&) = delete;
};

const int MAX_MESSAGES = 100; /** Max number of messages allowed in the database */

void write_worker(const std::string& room_id, const std::string& user_id, const std::string& message_content) {
    /** Lock the mutex to ensure that only one thread can write at a time */
    std::lock_guard<std::mutex> lock(write_mutex);

    MDB_txn* txn;  /** Transaction handle */
    MDB_dbi dbi;   /** Database handle */
    MDB_dbi meta_dbi; /** Meta database for tracking message count */

    /** Begin a new write transaction */
    if (mdb_txn_begin(env, nullptr, 0, &txn) != 0) {
        std::cerr << "Failed to begin write transaction.\n";
        return;
    }

    /** Open (or create) the main room database */
    if (mdb_dbi_open(txn, room_id.c_str(), MDB_CREATE, &dbi) != 0) {
        std::cerr << "Failed to open database.\n";
        mdb_txn_abort(txn); /** Abort the transaction if database opening fails */
        return;
    }

    /** Open the meta database for tracking message count */
    if (mdb_dbi_open(txn, "_meta", MDB_CREATE, &meta_dbi) != 0) {
        std::cerr << "Failed to open meta database.\n";
        mdb_txn_abort(txn); /** Abort the transaction if opening meta database fails */
        return;
    }

    MDB_val key, value;

    /** Check the current number of messages in the database */
    key.mv_size = sizeof("count");
    key.mv_data = (void*)"count";  /** Special key for storing the count of messages */
    int message_count = 0;

    if (mdb_get(txn, meta_dbi, &key, &value) == 0) {
        message_count = *static_cast<int*>(value.mv_data);  /** Extract the current message count */
    }

    /** If the message count exceeds the limit, delete the oldest message */
    if (message_count >= MAX_MESSAGES) {
        /** Get the oldest message using a cursor */
        MDB_cursor* cursor;
        if (mdb_cursor_open(txn, dbi, &cursor) == 0) {
            /** Retrieve the oldest message (the first entry in the cursor) */
            if (mdb_cursor_get(cursor, &key, &value, MDB_FIRST) == 0) {
                /** Remove the oldest message from the database */
                if (mdb_del(txn, dbi, &key, nullptr) != 0) {
                    std::cerr << "Failed to delete oldest message.\n";
                }
            }
            mdb_cursor_close(cursor);  /** Close the cursor */
        }
        /** Decrease the message count */
        message_count--;
    }

    /** Prepare the timestamp as the new message key */
    auto timestamp = std::chrono::system_clock::now().time_since_epoch();
    auto timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp).count();
    std::string timestamp_str = std::to_string(timestamp_ms);

    /** Create a combined key that includes user_id and timestamp */
    std::string combined_key = timestamp_str + ":" + user_id;

    /** Prepare the key-value pair for the new message */
    key.mv_size = combined_key.size();
    key.mv_data = (void*)combined_key.data();
    value.mv_size = message_content.size();
    value.mv_data = (void*)message_content.data();

    /** Write the new message into the room's database */
    if (mdb_put(txn, dbi, &key, &value, 0) == 0) {
        /** Update the message count in the meta database */
        message_count++;
        value.mv_size = sizeof(message_count);
        value.mv_data = &message_count;
        if (mdb_put(txn, meta_dbi, &key, &value, 0) != 0) {
            std::cerr << "Failed to update message count.\n";
            mdb_txn_abort(txn);
            return;
        }

        /** Commit the transaction if everything was successful */
        mdb_txn_commit(txn);
    } else {
        std::cerr << "Write failed.\n";
        mdb_txn_abort(txn); /** Abort the transaction if writing fails */
    }

    /** Close the database handles */
    mdb_dbi_close(env, dbi);
    mdb_dbi_close(env, meta_dbi);
}

void read_worker(const std::string& room_id, int n) {
    MDB_txn* txn;  /** Transaction handle */
    MDB_dbi dbi;   /** Database handle */
    MDB_cursor* cursor;  /** Cursor for iterating through the database */

    std::cout << "Starting read_worker\n";

    /** Start a read-only transaction */
    if (mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn) != 0) {
        std::cerr << "Failed to begin read transaction: " << mdb_strerror(errno) << "\n";
        return;
    }

    /** Open the database for the specified room_id */
    if (mdb_dbi_open(txn, room_id.c_str(), 0, &dbi) != 0) {
        std::cerr << "Failed to open database: " << mdb_strerror(errno) << "\n";
        mdb_txn_abort(txn); /** Abort the transaction if opening the database fails */
        return;
    }

    /** Open a cursor to iterate through the database */
    if (mdb_cursor_open(txn, dbi, &cursor) != 0) {
        std::cerr << "Failed to open cursor: " << mdb_strerror(errno) << "\n";
        mdb_txn_abort(txn); /** Abort the transaction if opening the cursor fails */
        mdb_dbi_close(env, dbi); /** Close the database handle */
        return;
    }

    MDB_val key, value;  /** Key-value pair to store the retrieved data */
    int messages_read = 0; /** Counter for the number of messages read */

    /** Start from the last message (most recent) */
    if (mdb_cursor_get(cursor, &key, &value, MDB_LAST) == 0) {
        /** Iterate backward (MDB_PREV) to get the previous messages */
        do {
            /** Display the retrieved value (message) */
            std::cout << "Read message: " << std::string((char*)value.mv_data, value.mv_size) << "\n";
            messages_read++; /** Increment the message counter */

            /** Stop if we have read `n` messages */
            if (messages_read >= n) {
                break;
            }

        /** Move to the previous message using MDB_PREV */
        } while (mdb_cursor_get(cursor, &key, &value, MDB_PREV) == 0);
    } else {
        std::cerr << "Failed to read the last message: " << mdb_strerror(errno) << "\n";
    }

    /** Commit the transaction */
    if (mdb_txn_commit(txn) != 0) {
        std::cerr << "Failed to commit transaction: " << mdb_strerror(errno) << "\n";
    }

    /** Close the cursor and database handle */
    mdb_cursor_close(cursor);
    mdb_dbi_close(env, dbi);

    std::cout << "Read operation completed.\n";
}

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

/** Function to populate the global unordered_map with active (1) and inactive (0) statuses */
void populateWebhookStatus(uint32_t bitmask)
{
    /** Clear the existing statuses in case this is called multiple times */
    webhookStatus.clear();

    for (uint32_t i = 0; i < 28; ++i)
    {
        Webhooks webhook = static_cast<Webhooks>(1 << i);
        webhookStatus[webhook] = (bitmask & (1 << i)) ? 1 : 0;
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

thread_local boost::asio::io_context io_context;                                                           // Thread-local io_context
thread_local boost::asio::ssl::context ssl_context(boost::asio::ssl::context::sslv23);                     // Thread-local ssl_context
thread_local std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> ssl_socket = nullptr; // Thread-local ssl_socket

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
        ssl_context.set_verify_mode(boost::asio::ssl::verify_none);

        if (!ssl_socket || !ssl_socket->lowest_layer().is_open()) {      
            ssl_socket = std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(io_context, ssl_context);

            /** Specify the endpoint using the IP address and port. 
             *  Ensure the IP address is correctly formatted. */
            boost::asio::ip::tcp::endpoint endpoint(
                boost::asio::ip::make_address("167.71.239.154"),
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

        /** Construct the HTTP request headers. */
        request_stream << "POST " << path << " HTTP/1.1\r\n"
                       << "Host: " << baseURL << "\r\n"
                       << "Connection: keep-alive\r\n"
                       << "Content-Type: application/json\r\n";

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
            sendHTTPSPOSTRequestFireAndForget(baseURL, path, body, headers);
        }else if (e.code() == boost::asio::error::connection_reset) {
            /** connection reset by peer */
            ssl_socket = nullptr;

            /** dangerous retry */
            sendHTTPSPOSTRequestFireAndForget(baseURL, path, body, headers);  
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

/** This function will parse and populate the userdata */
void populateUserData(std::string data) {
    nlohmann::json parsedJson = nlohmann::json::parse(data);

    UserData::getInstance().clientApiKey = parsedJson["client_api_key"];
    UserData::getInstance().adminApiKey = parsedJson["admin_api_key"];
    UserData::getInstance().msg_per_day = parsedJson["msg_per_day"].get<int>();
    UserData::getInstance().msg_per_second_per_connection = parsedJson["msg_per_second_per_connection"].get<int>();
    UserData::getInstance().connections = parsedJson["connections"].get<int>();
    UserData::getInstance().msg_size_allowed_in_bytes = parsedJson["msg_size_allowed_in_bytes"].get<int>();
    UserData::getInstance().webhooks = parsedJson["webhooks"].get<uint32_t>();
    UserData::getInstance().webHookBaseUrl = parsedJson["webhook_base_url"];
    UserData::getInstance().webhookPath = parsedJson["webhook_path"];
    UserData::getInstance().webhookSecret = parsedJson["webhook_secret"];

    populateWebhookStatus(UserData::getInstance().webhooks);
}

/**
 * @brief Fetch and populate user data from the metadata service
 */
void fetchAndPopulateUserData() {
    try {
        // std::string dropletId = sendHTTPRequest(INTERNAL_IP, "/metadata/v1/id").body;
        std::string dropletId = "468316038";

        /** Headers for the HTTP request */ 
        httplib::Headers headers = {
            {"secret", SECRET}
        };

        /** Make the HTTP request */ 
        std::string userData = sendHTTPSRequest(MASTER_SERVER_URL, "/api/v1/init/" + dropletId, headers).body;

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

/**
 * HTTP Webhook Error Codes
 * 
 * CONNECTION_BANNED - 3001
 * UID_ALREADY_EXIST - 3002
 * CONNECTION_LIMIT_REACHED - 3003
 * INVALID_API_KEY - 3004
 * INVALID_ROOM_ID_LENGTH - 3005
 * INVALID_ROOM_TYPE - 3006
 * ON_VERIFICATION_REQUEST_WEBHOOK_DISABLED - 3007
 * ON_RATE_LIMIT_EXCEEDED - 3008
 * ON_DAILY_MESSAGE_LIMIT_EXHAUSTED - 3009
 * ON_MESSAGE_SIZE_EXCEEDED - 3010
 * 
 * Verification Codes
 * 
 * INIT
 * 
 * INIT_PRIVATE_ROOM_VERIFICATION - 4001
 * INIT_PRIVATE_STATE_ROOM_VERIFICATION - 4002
 * 
 * Connection / Disconnection Codes
 * 
 * ON_CONNECTION_OPEN_PUBLIC_ROOM - 5001
 * ON_CONNECTION_OPEN_PRIVATE_ROOM - 5002
 * ON_CONNECTION_OPEN_PUBLIC_STATE_ROOM - 5003
 * ON_CONNECTION_OPEN_PRIVATE_STATE_ROOM - 5004
 * 
 * ON_ROOM_OCCUPIED_PUBLIC_ROOM - 5005
 * ON_ROOM_OCCUPIED_PRIVATE_ROOM - 5006
 * ON_ROOM_OCCUPIED_PUBLIC_STATE_ROOM - 5007
 * ON_ROOM_OCCUPIED_PRIVATE_STATE_ROOM - 5008
 * 
 * ON_MESSAGE_PUBLIC_ROOM - 5009
 * ON_MESSAGE_PRIVATE_ROOM - 5010
 * ON_MESSAGE_PUBLIC_STATE_ROOM - 5011
 * ON_MESSAGE_PRIVATE_STATE_ROOM - 5012
 * 
 * ON_CONNECTION_CLOSE_PUBLIC_ROOM - 5013
 * ON_CONNECTION_CLOSE_PRIVATE_ROOM - 5014
 * ON_CONNECTION_CLOSE_PUBLIC_STATE_ROOM - 5015
 * ON_CONNECTION_CLOSE_PRIVATE_STATE_ROOM - 5016
 * 
 * ON_ROOM_VACATED_PUBLIC_ROOM - 5017
 * ON_ROOM_VACATED_PRIVATE_ROOM - 5018
 * ON_ROOM_VACATED_PUBLIC_STATE_ROOM - 5019
 * ON_ROOM_VACATED_PRIVATE_STATE_ROOM - 5020
 * 
 * INFO
 * 
 * RATE_LIMIT_LIFTED - 6001
 * ON_MESSAGE_DROPPED - 6002
 */

/* uWebSocket worker thread function. */
void worker_t::work()
{
  /* Every thread has its own Loop, and uWS::Loop::get() returns the Loop for current thread.*/ 
  loop_ = uWS::Loop::get();

  /* uWS::App object / instance is used in uWS::Loop::defer(lambda_function) */
  app_ = std::make_shared<uWS::App>(
    uWS::App({
        .key_file_name = "ssl/privkey.pem",
        .cert_file_name = "ssl/cert.pem"
    })
  );

  /* Very simple WebSocket broadcasting echo server */
  app_->ws<PerSocketData>("/*", {
    /* Settings */
    .maxPayloadLength = 1024 * 1024,
    .idleTimeout = 60,
    .maxBackpressure = 4 * 1024,
    .closeOnBackpressureLimit = true,
    .resetIdleTimeoutOnSend = true,
    .sendPingsAutomatically = true,
    /* Handlers */
    .upgrade = [](auto *res, auto *req, auto *context) {
        struct UpgradeData {
            std::string secWebSocketKey;
            std::string secWebSocketProtocol;
            std::string secWebSocketExtensions;
            std::string rid;
            std::string key;
            std::string uid;
            struct us_socket_context_t *context;
            decltype(res) httpRes;
            bool aborted = false;
        } *upgradeData = new UpgradeData {
            std::string(req->getHeader("sec-websocket-key")),
            std::string(req->getHeader("sec-websocket-protocol")),
            std::string(req->getHeader("sec-websocket-extensions")),
            std::string(req->getQuery("rid")),
            std::string(req->getHeader("api-key")),
            std::string(req->getHeader("uid").empty() ? req->getHeader("sec-websocket-key") : req->getHeader("uid")),
            context,
            res
        };

        res->onAborted([=]() {
            upgradeData->aborted = true;
        });

        /**
         * Check if the user is banned and reject the connection
         */
        if(bannedConnections.find(upgradeData->uid) != bannedConnections.end()){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403 Forbidden");
            res->writeHeader("Content-Type", "application/json");
            res->end("CONNECTION_BANNED");

            if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"CONNECTION_BANNED\", "  
                        << "\"code\":3001, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"rid\":\"" << upgradeData->rid << "\", "
                        << "\"message\":\"This connection is banned by the admin.\"}";

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

        /**
         * check if a connection is already there with the same uid
         */
        if(uid.find(upgradeData->uid) != uid.end()){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403 Forbidden")->end("UID_ALREADY_EXIST");

            if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"UID_ALREADY_EXIST\", "  
                        << "\"code\":3002, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"rid\":\"" << upgradeData->rid << "\", "
                        << "\"message\":\"There is already a connection using this UID.\"}";

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

        /**
         * Check if the connection limit has been exceeded
         */
        if (globalConnectionCounter.load(std::memory_order_relaxed) >= UserData::getInstance().connections) {
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403 Forbidden")->end("CONNECTION_LIMIT_REACHED");

            if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"CONNECTION_LIMIT_REACHED\", "  
                        << "\"code\":3003, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"rid\":\"" << upgradeData->rid << "\", "
                        << "\"message\":\"You have reached the max limit of allowed connections.\"}";

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

        /**
         * Check if API key is valid or not
         */
        if(UserData::getInstance().clientApiKey != upgradeData->key){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403 Forbidden")->end("INVALID_API_KEY");

            if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"INVALID_API_KEY\", "  
                        << "\"code\":3004, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"rid\":\"" << upgradeData->rid << "\", "
                        << "\"message\":\"The API key is invalid.\"}";

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

        /**
         * Max rid size is 160 characters
         */
        if(upgradeData->rid.length() > 160 || upgradeData->rid.length() <= 0){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403 Forbidden")->end("INVALID_ROOM_ID_LENGTH");

            if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"INVALID_ROOM_ID_LENGTH\", "  
                        << "\"code\":3005, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"rid\":\"" << upgradeData->rid << "\", "
                        << "\"message\":\"The room id length should be between 1 to 160 characters.\"}";

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

        uint8_t roomType = -1;

        /**
         * rid name should start with "pub" or "pri"
         */
        if (upgradeData->rid.rfind("pub-", 0) == 0)
        {
            roomType = PUBLIC_ROOM;
        }
        else if (upgradeData->rid.rfind("pri-", 0) == 0)
        {
            roomType = PRIVATE_ROOM;
        }
        else if (upgradeData->rid.rfind("state-pub-", 0) == 0)
        {
            roomType = PUBLIC_STATE_ROOM;
        }
        else if (upgradeData->rid.rfind("state-pri-", 0) == 0)
        {
            roomType = PRIVATE_STATE_ROOM;
        }
        else
        {
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403 Forbidden")->end("INVALID_ROOM_TYPE");

            if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                        << "\"trigger\":\"INVALID_ROOM_TYPE\", "  
                        << "\"code\":3006, "
                        << "\"uid\":\"" << upgradeData->uid << "\", "
                        << "\"rid\":\"" << upgradeData->rid << "\", "
                        << "\"message\":\"The provided room type is invalid.\"}";

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

        if(roomType == PRIVATE_ROOM || roomType == PRIVATE_STATE_ROOM){
            if(webhookStatus[Webhooks::ON_VERIFICATION_REQUEST] == 1){
                std::ostringstream payload;

                if(roomType == PRIVATE_ROOM){
                    payload << "{\"event\":\"ON_VERIFICATION_REQUEST\", "
                            << "\"trigger\":\"INIT_PRIVATE_ROOM_VERIFICATION\", "
                            << "\"code\":4001, "
                            << "\"uid\":\"" << upgradeData->uid << "\", "
                            << "\"rid\":\"" << upgradeData->rid << "\"}";
                } else {
                    payload << "{\"event\":\"ON_VERIFICATION_REQUEST\", "
                            << "\"trigger\":\"INIT_PRIVATE_STATE_ROOM_VERIFICATION\", "
                            << "\"code\":4002, "
                            << "\"uid\":\"" << upgradeData->uid << "\", "
                            << "\"rid\":\"" << upgradeData->rid << "\"}";
                }

                std::string body = payload.str(); 
                
                int status = sendHTTPSPOSTRequest(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                ).status;

                if(status != 200){
                    totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
                    res->writeStatus("403 Forbidden")->end("ACCESS_DENIED");
                    return;
                }
            } else {
                totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
                res->writeStatus("403 Forbidden")->end("ACCESS_DENIED");

                if(webhookStatus[Webhooks::ON_CONNECTION_UPGRADE_REJECTED] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_CONNECTION_UPGRADE_REJECTED\", "
                            << "\"trigger\":\"ON_VERIFICATION_REQUEST_WEBHOOK_DISABLED\", "  
                            << "\"code\":3007, "
                            << "\"uid\":\"" << upgradeData->uid << "\", "
                            << "\"rid\":\"" << upgradeData->rid << "\", "
                            << "\"message\":\"Please enable ON_VERIFICATION_REQUEST webhook to use private rooms.\"}";

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

        if (!upgradeData->aborted) {
            upgradeData->httpRes->cork([upgradeData, roomType]() {
                upgradeData->httpRes->template upgrade<PerSocketData>({
                    /* We initialize PerSocketData struct here */
                    .rid = upgradeData->rid,
                    .key = upgradeData->key,
                    .uid = upgradeData->uid,
                    .roomType = roomType,  
                }, upgradeData->secWebSocketKey,
                    upgradeData->secWebSocketProtocol,
                    upgradeData->secWebSocketExtensions,
                    upgradeData->context
                );
            });
        } 
    },
    .open = [](auto *ws) {
        /**
         * Final check if a connection is already there with the same uid
         * probability of running this is very low
         */
        if (uid.find(ws->getUserData()->uid) != uid.end())
        {
            ws->end(1008, "{\"event\":\"UID_ALREADY_IN_USE\"}");
            return;
        }

        globalConnectionCounter.fetch_add(1, std::memory_order_relaxed);
        uid.insert(ws->getUserData()->uid);
        ws->subscribe(ws->getUserData()->rid);
        ws->subscribe(ws->getUserData()->uid);
        ws->subscribe(BROADCAST);
        topics[ws->getUserData()->rid].insert(ws->getUserData()->uid);

        /**
         * Send a message to self
         */
        std::ostringstream payload;
        payload << "{\"event\":\"CONNECTED_TO_ROOM\", \"uid\":\"" << ws->getUserData()->uid << "\"}";
        std::string result = payload.str(); 

        ws->send(result, uWS::OpCode::TEXT, true);

        /**
         * Broadcast the message to rest of the members of the group informing about the new connection
         */
        if(ws->getUserData()->roomType == PUBLIC_STATE_ROOM || ws->getUserData()->roomType == PRIVATE_STATE_ROOM) {
            std::ostringstream payload;
            payload << "{\"event\":\"SOMEONE_JOINED_THE_ROOM\", \"uid\":\"" << ws->getUserData()->uid << "\"}";
            std::string result = payload.str();

            std::for_each(::workers.begin(), ::workers.end(), [&ws, result](worker_t &w) {
                /** Check if the current thread ID matches the worker's thread ID */ 
                if (std::this_thread::get_id() == w.thread_->get_id()) {
                    ws->publish(ws->getUserData()->rid, result, uWS::OpCode::TEXT, true);
                }else{
                    /** Defer the message publishing to the worker's loop */ 
                    w.loop_->defer([&w, &ws, result]() {
                        w.app_->publish(ws->getUserData()->rid, result, uWS::OpCode::TEXT, true);
                    });
                }
            });
        }

        /** fire connection open webhook */
        if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PUBLIC_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_ROOM){
            std::ostringstream payload;
            payload << "{\"event\":\"ON_CONNECTION_OPEN_PUBLIC_ROOM\", "
                    << "\"code\":5001, "
                    << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                    << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                    << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                    << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        } else if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PRIVATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_ROOM){
            std::ostringstream payload;
            payload << "{\"event\":\"ON_CONNECTION_OPEN_PRIVATE_ROOM\", "
                    << "\"code\":5002, "
                    << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                    << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                    << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                    << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        } else if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PUBLIC_STATE_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_STATE_ROOM){
            std::ostringstream payload;
            payload << "{\"event\":\"ON_CONNECTION_OPEN_PUBLIC_STATE_ROOM\", "
                    << "\"code\":5003, "
                    << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                    << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                    << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                    << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        } else if(webhookStatus[Webhooks::ON_CONNECTION_OPEN_PRIVATE_STATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_STATE_ROOM){
            std::ostringstream payload;
            payload << "{\"event\":\"ON_CONNECTION_OPEN_PRIVATE_STATE_ROOM\", "
                    << "\"code\":5004, "
                    << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                    << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                    << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                    << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        }

        /** Room ocuupied webhooks */
        if(topics[ws->getUserData()->rid].size() == 1){
            if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PUBLIC_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_ROOM){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_OCCUPIED_PUBLIC_ROOM\", "
                        << "\"code\":5005, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                        << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                        << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            } else if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PRIVATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_ROOM){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_OCCUPIED_PRIVATE_ROOM\", "
                        << "\"code\":5006, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                        << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                        << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            } else if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PUBLIC_STATE_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_STATE_ROOM){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_OCCUPIED_PUBLIC_STATE_ROOM\", "
                        << "\"code\":5007, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                        << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                        << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            } else if(webhookStatus[Webhooks::ON_ROOM_OCCUPIED_PRIVATE_STATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_STATE_ROOM){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_OCCUPIED_PRIVATE_STATE_ROOM\", "
                        << "\"code\":5008, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                        << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                        << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            }
        }

        /** Check if we have reached the connection limit and fire webhook */
        if (webhookStatus[Webhooks::ON_MAX_CONNECTION_LIMIT_REACHED] == 1)
        {
            if (globalConnectionCounter.load(std::memory_order_relaxed) == UserData::getInstance().connections)
            {
                std::ostringstream payload;
                payload << "{\"event\":\"ON_MAX_CONNECTION_LIMIT_REACHED\", "
                        << "\"trigger\":\"CONNECTION_LIMIT_REACHED\", "  
                        << "\"code\":3003, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                        << "\"message\":\"You have reached the max limit of allowed connections.\"}";

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
    .message = [this](auto *ws, std::string_view message, uWS::OpCode opCode) {
        if(message.size() > UserData::getInstance().msg_size_allowed_in_bytes){
            ws->end(1009, "{\"event\":\"MESSAGE_SIZE_EXCEEDED\"}");

            if(webhookStatus[Webhooks::ON_MESSAGE_SIZE_EXCEEDED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_MESSAGE_SIZE_EXCEEDED\", "
                        << "\"code\":3010, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"msg_size_allowed_in_bytes\":\"" << UserData::getInstance().msg_size_allowed_in_bytes << "\"}";            
                
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
            if(ws->getBufferedAmount() > 4 * 1024 * 1024){
                ws->send("{\"event\":\"YOU_ARE_RATE_LIMITED\"}", uWS::OpCode::TEXT, true);
                ws->getUserData()->sendingAllowed = false;

                if(webhookStatus[Webhooks::ON_RATE_LIMIT_EXCEEDED] == 1){
                    std::ostringstream payload;
                    payload << "{\"event\":\"ON_RATE_LIMIT_EXCEEDED\", "
                            << "\"code\":3008, "
                            << "\"uid\":\"" << ws->getUserData()->uid << "\"}";

                    std::string body = payload.str(); 
                    
                    sendHTTPSPOSTRequestFireAndForget(
                        UserData::getInstance().webHookBaseUrl,
                        UserData::getInstance().webhookPath,
                        body,
                        {}
                    );
                }
            } else {
                if (UserData::getInstance().msg_per_day == -1 ? true : globalMessagesSent.load(std::memory_order_relaxed) < UserData::getInstance().msg_per_day) {
                    std::string rid = ws->getUserData()->rid;
                    unsigned int subscribers = app_->numSubscribers(rid);
                    globalMessagesSent.fetch_add(static_cast<unsigned long long>(subscribers), std::memory_order_relaxed);
                    totalPayloadSent.fetch_add(static_cast<unsigned long long>(message.size()) * static_cast<unsigned long long>(subscribers), std::memory_order_relaxed);   

                    /** Writing data to the file */
                    /**FileWriter& writer = GlobalFileWriter::getInstance();
                    writer.writeMessage(std::string(message));*/

                    write_worker(rid, ws->getUserData()->uid, std::string(message));

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
                    if(webhookStatus[Webhooks::ON_MESSAGE_PUBLIC_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_ROOM){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_MESSAGE_PUBLIC_ROOM\", "
                                << "\"code\":5009, "
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
                    } else if(webhookStatus[Webhooks::ON_MESSAGE_PRIVATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_ROOM){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_MESSAGE_PRIVATE_ROOM\", "
                                << "\"code\":5010, "
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
                    } else if(webhookStatus[Webhooks::ON_MESSAGE_PUBLIC_STATE_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_STATE_ROOM){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_MESSAGE_PUBLIC_STATE_ROOM\", "
                                << "\"code\":5011, "
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
                    } else if(webhookStatus[Webhooks::ON_MESSAGE_PRIVATE_STATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_STATE_ROOM){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_MESSAGE_PRIVATE_STATE_ROOM\", "
                                << "\"code\":5012, "
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
                } else {
                    droppedMessages.fetch_add(1, std::memory_order_relaxed);
                    ws->send("{\"event\":\"DAILY_MSG_LIMIT_EXHAUSTED\"}", uWS::OpCode::TEXT, true);

                    if(webhookStatus[Webhooks::ON_DAILY_MESSAGE_LIMIT_EXHAUSTED] == 1){
                        std::ostringstream payload;
                        payload << "{\"event\":\"ON_DAILY_MESSAGE_LIMIT_EXHAUSTED\", "
                                << "\"code\":3009, "
                                << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                                << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                                << "\"msg_per_day\":\"" << UserData::getInstance().msg_per_day << "\"}";              
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

            if(webhookStatus[Webhooks::ON_RATE_LIMIT_EXCEEDED] == 1){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_RATE_LIMIT_EXCEEDED\", "
                        << "\"code\":3008, "
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
        if(ws->getBufferedAmount() < 2 * 1024 * 1024){
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
        /* You don't need to handle this one, we automatically respond to pings as per standard */
        if (ws->getUserData()->key != UserData::getInstance().clientApiKey) {
            ws->end(1008, "{\"event\":\"API_KEY_INVALID\"}");
        } else if (bannedConnections.find(ws->getUserData()->uid) != bannedConnections.end()) {
            ws->end(1008, "{\"event\":\"YOU_HAVE_BEEN_BANNED\"}");
        }
    },
    .pong = [](auto *ws, std::string_view) {
        /* You don't need to handle this one either */
        if (ws->getUserData()->key != UserData::getInstance().clientApiKey) {
            ws->end(1008, "{\"event\":\"API_KEY_INVALID\"}");
        } else if (bannedConnections.find(ws->getUserData()->uid) != bannedConnections.end()) {
            ws->end(1008, "{\"event\":\"YOU_HAVE_BEEN_BANNED\"}");
        }
    },
    .close = [](auto *ws, int code, std::string_view message) {
        std::string rid = ws->getUserData()->rid;
        globalConnectionCounter.fetch_sub(1, std::memory_order_relaxed);
        topics[rid].erase(ws->getUserData()->uid);

        if(topics[rid].size() == 0){
            topics.erase(rid);
        }

        /**
         * Remove the uid from the set
         */
        uid.erase(ws->getUserData()->uid);

        /**
         * Broadcast the message to rest of the members of the group informing about the disconnection
         */
        if(ws->getUserData()->roomType == 2 || ws->getUserData()->roomType == 3){
            std::ostringstream payload;
            payload << "{\"event\":\"SOMEONE_LEFT_THE_ROOM\", \"uid\":\"" << ws->getUserData()->uid << "\"}";
            std::string result = payload.str();

            std::for_each(::workers.begin(), ::workers.end(), [rid, result](worker_t &w) {
                /** Defer the message publishing to the worker's loop */ 
                w.loop_->defer([&w, rid, result]() {
                    w.app_->publish(rid, result, uWS::OpCode::TEXT, true);
                });
            });
        }

        /** connection close webhooks */
        if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PUBLIC_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_ROOM){
            std::ostringstream payload; 

            payload << "{\"event\":\"ON_CONNECTION_CLOSE_PUBLIC_ROOM\", "
                    << "\"code\":5013, "
                    << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                    << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                    << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                    << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";
     
            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        } else if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PRIVATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_ROOM){
            std::ostringstream payload; 

            payload << "{\"event\":\"ON_CONNECTION_CLOSE_PRIVATE_ROOM\", "
                    << "\"code\":5014, "
                    << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                    << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                    << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                    << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";
     
            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        } else if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PUBLIC_STATE_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_STATE_ROOM){
            std::ostringstream payload; 

            payload << "{\"event\":\"ON_CONNECTION_CLOSE_PUBLIC_STATE_ROOM\", "
                    << "\"code\":5015, "
                    << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                    << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                    << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                    << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";
     
            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        } else if(webhookStatus[Webhooks::ON_CONNECTION_CLOSE_PRIVATE_STATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_STATE_ROOM){
            std::ostringstream payload; 

            payload << "{\"event\":\"ON_CONNECTION_CLOSE_PRIVATE_STATE_ROOM\", "
                    << "\"code\":5016, "
                    << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                    << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                    << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                    << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";
     
            std::string body = payload.str(); 
            
            sendHTTPSPOSTRequestFireAndForget(
                UserData::getInstance().webHookBaseUrl,
                UserData::getInstance().webhookPath,
                body,
                {}
            );
        }

        /** room vacate webhooks */
        if(topics[rid].size() == 0){
            if(webhookStatus[Webhooks::ON_ROOM_VACATED_PUBLIC_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_ROOM){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_VACATED_PUBLIC_ROOM\", "
                        << "\"code\":5017, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                        << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                        << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            } else if(webhookStatus[Webhooks::ON_ROOM_VACATED_PRIVATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_ROOM){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_VACATED_PRIVATE_ROOM\", "
                        << "\"code\":5018, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                        << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                        << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                std::string body = payload.str(); 
                
                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            } else if(webhookStatus[Webhooks::ON_ROOM_VACATED_PUBLIC_STATE_ROOM] == 1 && ws->getUserData()->roomType == PUBLIC_STATE_ROOM){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_VACATED_PUBLIC_STATE_ROOM\", "
                        << "\"code\":5019, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                        << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                        << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

                std::string body = payload.str();

                sendHTTPSPOSTRequestFireAndForget(
                    UserData::getInstance().webHookBaseUrl,
                    UserData::getInstance().webhookPath,
                    body,
                    {}
                );
            } else if(webhookStatus[Webhooks::ON_ROOM_VACATED_PRIVATE_STATE_ROOM] == 1 && ws->getUserData()->roomType == PRIVATE_STATE_ROOM){
                std::ostringstream payload;
                payload << "{\"event\":\"ON_ROOM_VACATED_PRIVATE_STATE_ROOM\", "
                        << "\"code\":5020, "
                        << "\"uid\":\"" << ws->getUserData()->uid << "\", "
                        << "\"rid\":\"" << ws->getUserData()->rid << "\", "
                        << "\"connections_in_room\":\"" << topics[ws->getUserData()->rid].size() << "\", "
                        << "\"total_connections\":\"" << globalConnectionCounter.load(std::memory_order_relaxed) << "\"}";

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
  }).get("/api/v1/metrics", [](auto *res, auto *req) {
        if(UserData::getInstance().clientApiKey.empty()){
            fetchAndPopulateUserData();
        }

        if (req->getHeader("api-key") != UserData::getInstance().adminApiKey) {
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("401 Unauthorized");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

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
	}).post("/api/v1/invalidate", [](auto *res, auto *req) {
        res->onAborted([]() {
            /** connection aborted */
        });

        if(UserData::getInstance().adminApiKey.empty()){
            fetchAndPopulateUserData();
        }

        if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

        if(req->getHeader("secret") != SECRET){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid secret key."})");
            return;
        }

        std::string body;
    
        body.reserve(1024);

        res->onData([res, req, body = std::move(body)](std::string_view data, bool last) mutable {
            body.append(data.data(), data.length());

            if (last) { 
                try {
                    /** Parse the JSON response */ 
                    populateUserData(body);

                    res->writeStatus("200 OK");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"message": "Metadata invalidated successfully."})");
                } catch (std::exception &e) {
                    res->writeStatus("400 Bad Request");
                    res->writeHeader("Content-Type", "application/json");
                    res->end(R"({"error": "Invalid JSON format."})");
                }
            }
        });
	}).get("/api/v1/rooms", [this](auto *res, auto *req) {
        res->onAborted([]() {
            /** connection aborted */
        });

        if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

        nlohmann::json response_json;

        for (const auto& topic : topics) {
            response_json.push_back(topic.first);  
        }

        res->writeStatus("200 OK");
        res->writeHeader("Content-Type", "application/json");
        res->end(response_json.dump());  
	}).put("/api/v1/broadcast", [this](auto *res, auto *req) {
        res->onAborted([]() {
            /** connection aborted */
        });

        if(req->getHeader("api-key") != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

        std::string_view message = req->getQuery("message");

        /** broadcast a message to all the rooms */
        std::for_each(::workers.begin(), ::workers.end(), [message](worker_t &w) {
            /** Defer the message publishing to the worker's loop */ 
            w.loop_->defer([&w, message]() {
                w.app_->publish(BROADCAST, message, uWS::OpCode::TEXT, true);
            });
        });

        res->writeStatus("200 OK");
        res->writeHeader("Content-Type", "application/json");
        res->end(R"({"message": "Broadcasted successfully."})");
	}).put("/api/v1/rooms/:rid/broadcast", [this](auto *res, auto *req) {
        res->onAborted([]() {
            /** connection aborted */
        });

        std::string_view message = req->getQuery("message");
        std::string_view rid = req->getParameter("rid");
        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

        /** broadcast a message to a specific room */
        std::for_each(::workers.begin(), ::workers.end(), [message, rid](worker_t &w) {
            /** Defer the message publishing to the worker's loop */ 
            w.loop_->defer([&w, message, rid]() {
                w.app_->publish(rid, message, uWS::OpCode::TEXT, true);
            });
        });

        res->writeStatus("200 OK");
        res->writeHeader("Content-Type", "application/json");
        res->end(R"({"message": "Broadcasted successfully."})");
	}).put("/api/v1/connections/:uid/broadcast", [this](auto *res, auto *req) {
        res->onAborted([]() {
            /** connection aborted */
        });

        std::string_view message = req->getQuery("message");
        std::string_view uid = req->getParameter("uid");
        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

        /** broadcast a message to a specific member of a room */
        std::for_each(::workers.begin(), ::workers.end(), [message, uid](worker_t &w) {
            /** Defer the message publishing to the worker's loop */ 
            w.loop_->defer([&w, message, uid]() {
                w.app_->publish(uid, message, uWS::OpCode::TEXT, true);
            });
        });

        res->writeStatus("200 OK");
        res->writeHeader("Content-Type", "application/json");
        res->end(R"({"message": "Broadcasted successfully."})");
	}).put("/api/v1/connections/:uid/ban", [this](auto *res, auto *req) {
        res->onAborted([]() {
            /** connection aborted */
        });

        std::string_view uid = req->getParameter("uid");
        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

        bannedConnections.insert(std::string(uid));

        res->writeStatus("200 OK");
        res->writeHeader("Content-Type", "application/json");
        res->end(R"({"message": "Banned Successfully!"})");
	}).put("/api/v1/connections/:uid/unban", [this](auto *res, auto *req) {
        res->onAborted([]() {
            /** connection aborted */
        });

        std::string_view uid = req->getParameter("uid");
        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

        bannedConnections.erase(std::string(uid));

        res->writeStatus("200 OK");
        res->writeHeader("Content-Type", "application/json");
        res->end(R"({"message": "Unbanned Successfully!"})");
	}).get("/api/v1/rooms/:rid/connections", [this](auto *res, auto *req) {
        res->onAborted([]() {
            /** connection aborted */
        });

        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

        nlohmann::json json_response = topics[std::string(req->getParameter("rid"))];

        res->writeStatus("200 OK");
        res->writeHeader("Content-Type", "application/json");
        res->end(json_response.dump());  
	}).get("/api/v1/connections/banned", [this](auto *res, auto *req) {
        res->onAborted([]() {
            /** connection aborted */
        });

        std::string_view apiKey = req->getHeader("api-key");

        if(apiKey != UserData::getInstance().adminApiKey){
            totalRejectedRquests.fetch_add(1, std::memory_order_relaxed);
            res->writeStatus("403");
            res->writeHeader("Content-Type", "application/json");
            res->end(R"({"error": "Unauthorized access. Invalid API key."})");
            return;
        }

        nlohmann::json json_response = bannedConnections;

        res->writeStatus("200 OK");
        res->writeHeader("Content-Type", "application/json");
        res->end(json_response.dump());  
	}).get("/api/v1/ping", [](auto *res, auto */*req*/) {
        res->writeStatus("200 OK");
	    res->end("pong!");
	}).listen(PORT, [this](auto *token) {
    listen_socket_ = token;
    if (listen_socket_) {
        std::cout << "Thread " << std::this_thread::get_id() << " listening on port " << PORT << std::endl;
    }
    else{
        std::cout << "Thread " << std::this_thread::get_id() << " failed to listen on port " << PORT << std::endl;
    }
  });

  app_->run();

  /** cleanup */
  io_context.stop();

  std::cout << "Thread " << std::this_thread::get_id() << " exiting" << std::endl;
}

/* Main */
int main() {
  /** Fetch and populated data before starting the threads */
  fetchAndPopulateUserData();
  init_env();

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