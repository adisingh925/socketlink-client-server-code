#pragma once

/**
 * Compiled-in server configuration (standalone mode) published as immutable
 * snapshots, plus the feature-flag registry.
 */
#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

enum class Features : uint32_t {
    ENABLE_MYSQL_INTEGRATION = 1 << 0,
};

/** read features, thread safe */
int getFeatureStatus(Features feature);

/** Decode a bitmask into the feature-status map (1 = active, 0 = inactive). */
void populateFeatureStatus(uint32_t bitmask);

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

    /** OPTIONAL per-user auth (empty = disabled, uid header is trusted as-is —
     *  fine when the only client is the operator's own backend). When set, every
     *  uid-bearing request (WS upgrade, subscribe/unsubscribe, cache read) must
     *  also carry a `token` header of the form
     *      "<expiry-unix>.<hex hmac_sha256(secret, "<uid>.<expiry-unix>")>"
     *  minted by the operator's backend, so the shared client key can no longer
     *  impersonate arbitrary uids. */
    std::string connectionTokenSecret;

    /** webhook configuration */
    std::string webHookBaseUrl;
    std::string webhookPath;
    std::string webhookSecret;
    uint64_t webhooks = 0;
    std::string webhookIP;
    /** webhook endpoint port (always HTTPS; internal endpoints often use 8443) */
    int webhookPort = 443;

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

/** Standalone / self-hosted mode: config is compiled in (see main()); there is no
 *  master server and no config file. /api/v1/invalidate is authenticated with the
 *  admin api key and can update the in-memory config snapshot at runtime. */

/** Apply a JSON config update (from /api/v1/invalidate) by clone-modify-publish.
 *  Returns 1 (reconnect MySQL), -1 (flush + disconnect MySQL), 2 (restart needed)
 *  or 0 (nothing further to do). */
int populateUserData(std::string data);

/** Re-resolve the webhook host's IP into a fresh config snapshot. Called by the
 *  webhook sender when a connect fails: the IP is captured once at config time,
 *  so a rotated load-balancer IP would otherwise break webhooks until the next
 *  manual /invalidate. */
void refreshWebhookIP();

/** Verify a `token` header proves ownership of `uid` (see connectionTokenSecret).
 *  Always true while token auth is disabled (empty secret). */
bool verifyConnectionToken(const std::string& uid, std::string_view token);
