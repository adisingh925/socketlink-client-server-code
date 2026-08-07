#include "Config.h"

#include <ctime>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include "Util.h"
#include "Webhooks.h"
#include "json.hpp"

std::unordered_map<Features, int> featureStatus;
std::shared_mutex featureMutex;

/** read features, thread safe */
int getFeatureStatus(Features feature) {
    std::shared_lock<std::shared_mutex> lock(featureMutex);

    auto it = featureStatus.find(feature);
    return (it != featureStatus.end()) ? it->second : 0;
}

/** Serializes config writers (populateUserData) so concurrent /invalidate calls
 *  don't lose updates via clone-modify-publish races. */
std::mutex configWriteMutex;

void populateFeatureStatus(uint32_t bitmask) {
    std::unique_lock<std::shared_mutex> lock(featureMutex);

    for (uint32_t i = 0; i < 1; ++i) {
        Features feature = static_cast<Features>(1 << i);
        featureStatus[feature] = (bitmask & (1 << i)) ? 1 : 0;
    }
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

    if (parsedJson.contains("connection_token_secret") && !parsedJson["connection_token_secret"].is_null()) {
        userData.connectionTokenSecret = parsedJson["connection_token_secret"].get<std::string>();
    }

    if (parsedJson.contains("connections") && !parsedJson["connections"].is_null()) {
        userData.connections = parsedJson["connections"].get<int>();
    }

    /** maxPayloadLength is baked into the uWS websocket behavior at startup, so a
     *  CHANGE here (like the other socket-level settings below) requires the
     *  restart action — previously it was updated in the snapshot but silently
     *  never reached the websocket layer. */
    if (parsedJson.contains("msg_size_allowed_in_bytes") && !parsedJson["msg_size_allowed_in_bytes"].is_null()) {
        unsigned int v = parsedJson["msg_size_allowed_in_bytes"].get<unsigned int>();
        if (v != userData.msgSizeAllowedInBytes) {
            userData.msgSizeAllowedInBytes = v;
            needsDBUpdate = 2;
        }
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
        unsigned long long v = parsedJson["max_storage_allowed_in_gb"].get<unsigned long long>() * 1024ULL * 1024 * 1024;
        if (v != userData.lmdbDatabaseSizeInBytes) {
            userData.lmdbDatabaseSizeInBytes = v;
            /** the LMDB map size is set once in init_env — a change only takes
             *  effect through the restart action, same as the socket settings */
            needsDBUpdate = 2;
        }
    }

    if (parsedJson.contains("lmdb_commit_batch_size") && !parsedJson["lmdb_commit_batch_size"].is_null()) {
        userData.lmdbCommitBatchSize = parsedJson["lmdb_commit_batch_size"].get<int>();
    }

    if (parsedJson.contains("db_commit_batch_size") && !parsedJson["db_commit_batch_size"].is_null()) {
        userData.mysqlDBCommitBatchSize = parsedJson["db_commit_batch_size"].get<int>();
    }

    /** Socket-level settings are frozen into the uWS behavior at startup — an
     *  actual CHANGE (same value = no-op) triggers the restart action so they
     *  take effect. (The previous compare-against-60/0 branching was vestigial
     *  and restarted even when the value was unchanged.) */
    if (parsedJson.contains("idle_timeout_in_seconds") && !parsedJson["idle_timeout_in_seconds"].is_null()) {
        unsigned short v = parsedJson["idle_timeout_in_seconds"].get<unsigned short>();
        if (v != userData.idleTimeoutInSeconds) {
            userData.idleTimeoutInSeconds = v;
            needsDBUpdate = 2;
        }
    }

    if (parsedJson.contains("max_lifetime_in_minutes") && !parsedJson["max_lifetime_in_minutes"].is_null()) {
        unsigned short v = parsedJson["max_lifetime_in_minutes"].get<unsigned short>();
        if (v != userData.maxLifetimeInMinutes) {
            userData.maxLifetimeInMinutes = v;
            needsDBUpdate = 2;
        }
    }

    if (parsedJson.contains("max_backpressure_in_bytes") && !parsedJson["max_backpressure_in_bytes"].is_null()) {
        unsigned int v = parsedJson["max_backpressure_in_bytes"].get<unsigned int>();
        if (v != userData.maxBackpressureInBytes) {
            userData.maxBackpressureInBytes = v;
            needsDBUpdate = 2;
        }
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

void refreshWebhookIP() {
    std::lock_guard<std::mutex> writeLock(configWriteMutex);
    UserData userData = UserData::getInstance();

    if (userData.webHookBaseUrl.empty()) {
        return;
    }

    resolveAndStoreIPAddress(userData, userData.webHookBaseUrl);
    UserData::publish(new UserData(std::move(userData)));
}

bool verifyConnectionToken(const std::string& uid, std::string_view token) {
    const std::string& secret = UserData::getInstance().connectionTokenSecret;
    if (secret.empty()) {
        return true; /** token auth disabled: uid is trusted (single-tenant mode) */
    }

    /** token = "<expiry-unix>.<hex signature>" */
    size_t dot = token.find('.');
    if (dot == std::string_view::npos || dot == 0 || dot + 1 >= token.size()) {
        return false;
    }

    std::string_view expiryStr = token.substr(0, dot);
    std::string_view signature = token.substr(dot + 1);

    long long expiry = 0;
    for (char c : expiryStr) {
        if (c < '0' || c > '9') {
            return false;
        }
        expiry = expiry * 10 + (c - '0');
        if (expiry > 253402300799LL) { /** sanity cap: year 9999 */
            return false;
        }
    }

    if (expiry < static_cast<long long>(std::time(nullptr))) {
        return false; /** expired */
    }

    std::string message = uid;
    message += '.';
    message.append(expiryStr.data(), expiryStr.size());

    unsigned char hmac_result[HMAC_SHA256_DIGEST_LENGTH];
    hmac_sha256(secret.c_str(), secret.length(), message.c_str(), message.length(), hmac_result);

    return constantTimeEquals(to_hex(hmac_result, HMAC_SHA256_DIGEST_LENGTH), signature);
}
