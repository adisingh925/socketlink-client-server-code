#pragma once

/**
 * Asynchronous logging: call sites format only; a dedicated thread does all I/O.
 */
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <ctime>
#include <deque>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

constexpr bool LOGS_ENABLED = true;

enum class LogLevel { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

/** Minimum level that is actually emitted (runtime-adjustable). Suppressed
 *  levels cost one relaxed atomic load and a branch at the call site. */
inline std::atomic<int> g_logLevel{static_cast<int>(LogLevel::INFO)};

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
