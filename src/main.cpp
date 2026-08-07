#include <signal.h>
#include <sys/resource.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <thread>

#include "Config.h"
#include "LmdbStore.h"
#include "Logging.h"
#include "MemoryGuard.h"
#include "ServerState.h"

int main() {
    /** Block SIGTERM/SIGINT FIRST — before anything spawns a thread (the first
     *  log() call below starts the AsyncLogger writer). A process-directed signal
     *  is delivered to ANY thread that hasn't blocked it, so a thread created
     *  before this mask would take the default action (instant termination) and
     *  the graceful-shutdown sigwait thread below would never see the signal. */
    sigset_t shutdownSignals;
    sigemptyset(&shutdownSignals);
    sigaddset(&shutdownSignals, SIGTERM);
    sigaddset(&shutdownSignals, SIGINT);
    pthread_sigmask(SIG_BLOCK, &shutdownSignals, nullptr);

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

    /** The compiled-in defaults are placeholders: anyone who reads the source knows
     *  them, so running with them means every client is effectively an admin. */
    if (UserData::getInstance().clientApiKey == "change-me-client-key" ||
        UserData::getInstance().adminApiKey == "change-me-admin-key") {
        log(LogLevel::WARN, "SECURITY: default API key(s) in use (change-me-*). Set real keys before rebuilding, "
                            "or override them at runtime via POST /api/v1/invalidate "
                            "{\"client_api_key\":..., \"admin_api_key\":...}.");
    }

    /** Clamp the advertised connection limit to what memory can actually hold.
     *  The compiled-in default (100k) exceeds a 1 GB budget by ~2.5x, and an
     *  unreachable cap is worse than none: the kernel OOM-kills the process —
     *  taking every established connection with it — before the cap sheds
     *  anything. ~15 KB/connection measured (incl. kernel socket buffers). */
    /** the operator's intent, captured before clamping: the adaptive cap may grow
     *  back up to this but never past it */
    const int configuredConnections = UserData::getInstance().connections;
    {
        unsigned long long memLimit = memoryLimitBytes();
        int safeCap = safeConnectionCap(memLimit);
        int configured = configuredConnections;
        if (safeCap > 0 && configured > safeCap) {
            log(LogLevel::WARN, "Connection limit ", configured, " exceeds what ", memLimit / (1024 * 1024),
                " MiB can hold; clamping to ", safeCap,
                " (override the estimate with SL_BYTES_PER_CONN, or raise the memory limit)");
            setConnectionLimit(safeCap);
        } else if (memLimit > 0) {
            log(LogLevel::INFO, "Connection limit ", configured, " fits the ", memLimit / (1024 * 1024),
                " MiB memory budget (headroom for ~", safeCap, ")");
        }
    }

    /** The startup clamp is only a starting point — it uses a fixed
     *  bytes-per-connection guess that is wrong for some workload either way.
     *  Let the guard re-size the cap from MEASURED cost (never above the
     *  operator's configured value), so light traffic earns a bigger cap and
     *  heavy fan-out shrinks it before memory becomes a problem. */
    enableAdaptiveCap(&globalConnectionCounter, configuredConnections);

    /** Backstop for everything neither estimate nor measurement predicts in time
     *  (ramp bursts, payload spikes): pause admission under real memory pressure
     *  instead of dying. */
    startMemoryGuard();

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

    /** Graceful shutdown: SIGTERM/SIGINT are blocked process-wide (first thing in
     *  main), so they queue until this dedicated thread collects them via sigwait —
     *  a plain signal handler could not safely flush LMDB/MySQL. Without this, a
     *  systemd stop / Ctrl-C lost up to ~1s of buffered LMDB writes (the
     *  flush-timer window) and any partially-filled MySQL batches. */
    workers.resize(numThreads);

    std::thread([shutdownSignals]() {
        int sig = 0;
        sigwait(&shutdownSignals, &sig);
        log(LogLevel::INFO, "Received signal ", sig, ": flushing persistence and shutting down");

        /** flush every worker's thread-local LMDB batch on its own loop and the
         *  MySQL writer's pending batch on its thread, give them a moment, then
         *  sync the LMDB map to disk. (loop_ may still be null if the signal
         *  beats a worker's startup.) */
        for (auto& w : ::workers) {
            if (w.loop_) {
                w.loop_->defer([]() { write_worker("", "", true); });
            }
        }
        MySQLWriter::getInstance().requestFlush();
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        mdb_env_sync(env, 1);

        /** _Exit, not exit(): running static destructors while 20 worker threads
         *  still use the global maps hangs/UBs. Everything durable was flushed
         *  above (the async logger flushes per batch, so the log line is out). */
        std::_Exit(0);
    }).detach();

    for (auto& w : workers) {
        w.thread_ = std::make_shared<std::thread>([&w]() { w.work(); });
    }

    std::for_each(workers.begin(), workers.end(), [](worker_t& w) { w.thread_->join(); });

    log(LogLevel::INFO, "All workers exited; shutting down.");

    mdb_env_close(env);

    return 0;
}
