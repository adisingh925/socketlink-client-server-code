#include "Webhooks.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <vector>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

#include "Config.h"
#include "Logging.h"
#include "ServerState.h"
#include "Util.h"

/** enabled-webhook bitmap; guarded by webhookMutex (read on every event) */
std::unordered_map<Webhooks, int> webhookStatus;
std::shared_mutex webhookMutex;

/** Thread local variables (one webhook connection per sending thread) */
thread_local boost::asio::io_context io_context;
thread_local boost::asio::ssl::context ssl_context(boost::asio::ssl::context::sslv23);
thread_local std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> ssl_socket = nullptr;

/** Decode a bitmask into the webhook-status map (1 = active, 0 = inactive). */
void populateWebhookStatus(uint8_t bitmask) {
    std::unique_lock<std::shared_mutex> lock(webhookMutex);

    /** bits 1..6 (values 2..64): i < 7, not i < 6 — the old bound silently made
     *  ON_ROOM_VACATED (1 << 6) impossible to enable */
    for (uint8_t i = 0; i < 7; ++i) {
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

/**
 * Read exactly ONE complete HTTP response from the thread-local keep-alive webhook
 * connection and return its status code (0 on read/parse failure).
 *
 * Draining the response is not optional on a keep-alive connection: previously
 * fire-and-forget sends never read responses at all and the sync path read only
 * the headers, so unread bytes accumulated in the stream and a later private-room
 * verification could parse a PREVIOUS response's leftovers as its status line
 * (wrong allow/deny decisions, no attacker required). The body is consumed via
 * Content-Length; when the length is unknown (chunked / missing) or the server
 * announced Connection: close, the connection is dropped instead — the next
 * request reconnects, which can never desync.
 */
static int readAndDrainWebhookResponse() {
    boost::asio::streambuf response_buffer;
    boost::system::error_code ec;

    boost::asio::read_until(*ssl_socket, response_buffer, "\r\n\r\n", ec);
    if (ec) {
        log(LogLevel::ERROR, "Error reading webhook response : ", ec.message());
        ssl_socket = nullptr; /** stream state unknown — do not reuse */
        return 0;
    }

    std::istream response_stream(&response_buffer);
    std::string status_line;
    std::getline(response_stream, status_line);
    if (!status_line.empty() && status_line.back() == '\r') {
        status_line.pop_back();
    }
    if (status_line.empty()) {
        log(LogLevel::INFO, "Empty response line!");
        ssl_socket = nullptr;
        return 0;
    }

    /** parse: HTTP version, status code */
    std::istringstream status_stream(status_line);
    std::string http_version;
    unsigned int status_code = 0; /* 0 if the status line fails to parse */
    status_stream >> http_version >> status_code;

    /** scan the headers for message-framing info */
    long long contentLength = -1;
    bool chunked = false;
    bool connectionClose = false;
    std::string line;
    while (std::getline(response_stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            break; /** end of headers */
        }
        std::string lower(line);
        std::transform(
            lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        if (lower.rfind("content-length:", 0) == 0) {
            contentLength = std::atoll(line.c_str() + 15);
        } else if (lower.rfind("transfer-encoding:", 0) == 0 && lower.find("chunked") != std::string::npos) {
            chunked = true;
        } else if (lower.rfind("connection:", 0) == 0 && lower.find("close") != std::string::npos) {
            connectionClose = true;
        }
    }

    if (chunked || contentLength < 0 || connectionClose) {
        /** body length unknown (or the peer will close anyway): drop the
         *  connection rather than risk misframing the next response */
        ssl_socket = nullptr;
        return (int)status_code;
    }

    /** drain the body — read_until may already have buffered part of it */
    long long buffered = (long long)response_buffer.size();
    if (buffered < contentLength) {
        boost::asio::read(
            *ssl_socket, response_buffer, boost::asio::transfer_exactly((size_t)(contentLength - buffered)), ec);
        if (ec) {
            ssl_socket = nullptr; /** short read — stream unusable */
        }
    }

    return (int)status_code;
}

/** Synchronously send an HTTPS POST webhook on the CALLING thread. This blocks on
 *  TCP connect / SSL handshake / write / response read, so it must NOT be called
 *  directly from a uWS event-loop thread for fire-and-forget events — use the
 *  sendHTTPSPOSTRequestFireAndForget wrapper, which offloads to a dispatcher thread.
 *  The synchronous path is used directly only when a status code is needed
 *  (waitForResponse == true, e.g. private-room verification). */
static int sendWebhookBlocking(
    const std::string& baseURL, const std::string& path, const std::string& body,
    const std::map<std::string, std::string>& headers, bool waitForResponse) {
    for (int attempt = 0; attempt < 2; ++attempt) {
        try {
            if (UserData::getInstance().webhookIP.empty()) {
                /** DNS is not resolved, returning */
                return 0;
            }

            /** Certificate verification is intentionally disabled: in this
             *  deployment the webhook endpoint lives behind the operator's own
             *  load balancer / private network, so the network is the trust
             *  boundary. If webhooks ever target arbitrary public endpoints,
             *  this must become verify_peer + SNI + hostname verification —
             *  the verification webhook's status code GRANTS private-room access. */
            ssl_context.set_verify_mode(boost::asio::ssl::verify_none);

            if (!ssl_socket || !ssl_socket->lowest_layer().is_open()) {
                ssl_socket =
                    std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(io_context, ssl_context);

                boost::asio::ip::tcp::endpoint endpoint(
                    boost::asio::ip::make_address(UserData::getInstance().webhookIP),
                    static_cast<unsigned short>(UserData::getInstance().webhookPort));

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
                hmac_sha256(
                    UserData::getInstance().webhookSecret.c_str(), UserData::getInstance().webhookSecret.length(),
                    body.c_str(), body.length(), hmac_result);

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

            /** ALWAYS read + drain the response, even for fire-and-forget: leaving
             *  it unread would desync the keep-alive stream (see the drain helper).
             *  For fire-and-forget this costs one RTT on the dispatcher thread —
             *  never on an event loop. Counters are now honest: 2xx = success. */
            int status_code = readAndDrainWebhookResponse();

            if (status_code >= 200 && status_code < 300) {
                totalSuccessWebhookCalls.fetch_add(1, std::memory_order_relaxed);
            } else {
                totalFailedWebhookCalls.fetch_add(1, std::memory_order_relaxed);
            }

            return waitForResponse ? status_code : 0;
        } catch (const boost::system::system_error& e) {
            log(LogLevel::ERROR, "Error in sendWebhookBlocking : ", e.what());

            ssl_socket = nullptr;

            /** the endpoint's IP may have rotated since it was resolved at config
             *  time (it sits behind the operator's load balancer) — re-resolve
             *  before the retry so webhooks self-heal instead of failing until
             *  the next manual /invalidate */
            refreshWebhookIP();

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
    void
    enqueue(std::string baseURL, std::string path, std::string body, std::map<std::string, std::string> headers = {}) {
        bool droppedOne = false;
        size_t jobBytes = body.size() + path.size() + baseURL.size() + 64;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            /** Bound the queue by BOTH entry count and total bytes. A count-only bound
             *  (100k) is a ~1 GB memory hole at the 10 KB message cap, since ON_MESSAGE
             *  embeds the whole message — measured OOMing a 1 GB container. Drop oldest
             *  until this job fits within both bounds (but always keep at least the room
             *  for this one job). */
            while ((queue_.size() >= maxQueueSize_ || queuedBytes_ + jobBytes > maxQueueBytes_) && !queue_.empty()) {
                queuedBytes_ -= queue_.front().bytes;
                queue_.pop_front();
                droppedWebhookCalls_.fetch_add(1, std::memory_order_relaxed);
                droppedOne = true;
            }
            queue_.push_back(Job{std::move(baseURL), std::move(path), std::move(body), std::move(headers), jobBytes});
            queuedBytes_ += jobBytes;
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
        size_t bytes = 0; /* approximate memory footprint, for the byte bound */
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
                queuedBytes_ -= job.bytes;
                queue_.pop_front();
            }
            /** Blocking send happens on this dedicated thread, never on an event loop.
             *  Guarded: an exception escaping a std::thread body calls std::terminate. */
            try {
                sendWebhookBlocking(job.baseURL, job.path, job.body, job.headers, false);
            } catch (const std::exception& e) {
                log(LogLevel::ERROR, "Webhook dispatcher: ", e.what());
            } catch (...) {
                log(LogLevel::ERROR, "Webhook dispatcher: unknown exception");
            }
        }
    }

    std::deque<Job> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool running_ = true;
    std::atomic<unsigned long long> droppedWebhookCalls_{0};
    size_t queuedBytes_ = 0;
    static constexpr size_t maxQueueSize_ = 100000;
    /** total queued payload budget: bounds memory regardless of message size.
     *  100k entries at the 10 KB message cap would otherwise be ~1 GB. */
    static constexpr size_t maxQueueBytes_ = 64ULL * 1024 * 1024;
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
int sendHTTPSPOSTRequestFireAndForget(
    const std::string& baseURL, const std::string& path, const std::string& body,
    const std::map<std::string, std::string>& headers, bool waitForResponse) {
    if (waitForResponse) {
        return sendWebhookBlocking(baseURL, path, body, headers, true);
    }

    WebhookDispatcher::getInstance().enqueue(baseURL, path, body, headers);
    return 0;
}

std::string resolveHostToIPv4(const std::string& hostname) {
    struct addrinfo hints, *res = nullptr;
    char ipAddress[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (status != 0 || !res) {
        log(LogLevel::ERROR, "getaddrinfo error : ", gai_strerror(status));
        return "";
    }

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipAddress, sizeof(ipAddress));

    freeaddrinfo(res);
    return ipAddress;
}

/**
 * Resolves the IPv4 address for `hostname` into the config snapshot being built.
 * NOTE: this blocks (getaddrinfo); callers holding configWriteMutex stall every
 * other config writer for the duration — prefer resolveHostToIPv4() outside the
 * lock where possible (see refreshWebhookIP).
 */
void resolveAndStoreIPAddress(UserData& ud, const std::string& hostname) {
    std::string ip = resolveHostToIPv4(hostname);
    if (!ip.empty()) {
        ud.webhookIP = std::move(ip);
    }
}

void stopWebhookIoContext() {
    io_context.stop();
}

unsigned long long droppedWebhookCount() {
    return WebhookDispatcher::getInstance().droppedCount();
}

/**
 * Small dedicated pool for BLOCKING verification webhooks (waitForResponse=true).
 * A handful of threads bound the damage a slow endpoint can do; each pool thread
 * reuses its own thread-local keep-alive connection (see sendWebhookBlocking).
 * The queue is bounded — when full, enqueue fails and the caller rejects instead
 * of queueing unbounded latency.
 */
class VerificationPool {
public:
    static VerificationPool& getInstance() {
        static VerificationPool instance;
        return instance;
    }

    bool enqueue(std::string baseURL, std::string path, std::string body, std::function<void(int)> onDone) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.size() >= maxQueueSize_) {
                return false;
            }
            queue_.push_back(Job{std::move(baseURL), std::move(path), std::move(body), std::move(onDone)});
        }
        cv_.notify_one();
        return true;
    }

    VerificationPool(const VerificationPool&) = delete;
    VerificationPool& operator=(const VerificationPool&) = delete;

private:
    struct Job {
        std::string baseURL;
        std::string path;
        std::string body;
        std::function<void(int)> onDone;
    };

    VerificationPool() {
        for (size_t i = 0; i < numThreads_; ++i) {
            threads_.emplace_back([this]() { run(); });
        }
    }

    ~VerificationPool() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
        cv_.notify_all();
        for (auto& t : threads_) {
            if (t.joinable()) {
                t.join();
            }
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
            /** guarded: std::terminate otherwise (see the dispatcher above) */
            int status = 0;
            try {
                status = sendWebhookBlocking(job.baseURL, job.path, job.body, {}, true);
            } catch (const std::exception& e) {
                log(LogLevel::ERROR, "Verification webhook: ", e.what());
            } catch (...) {
                log(LogLevel::ERROR, "Verification webhook: unknown exception");
            }
            try {
                job.onDone(status);
            } catch (...) {
                log(LogLevel::ERROR, "Verification callback threw");
            }
        }
    }

    std::deque<Job> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool running_ = true;
    static constexpr size_t numThreads_ = 4;
    static constexpr size_t maxQueueSize_ = 1024;
    std::vector<std::thread> threads_;
};

bool enqueueVerificationWebhook(
    std::string baseURL, std::string path, std::string body, std::function<void(int)> onDone) {
    return VerificationPool::getInstance().enqueue(
        std::move(baseURL), std::move(path), std::move(body), std::move(onDone));
}
