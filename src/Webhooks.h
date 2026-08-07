#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>

class UserData;

/** webhooks */
enum class Webhooks : uint8_t {
    /** Message-related events */
    ON_MESSAGE = 1 << 1, /** value 2 */

    /** Connection verification events */
    ON_VERIFICATION_REQUEST = 1 << 2, /** value 4 */

    /** Connection open events */
    ON_SUBSCRIBE = 1 << 3, /** value 8 */

    /** Connection close events */
    ON_UNSUBSCRIBE = 1 << 4, /** value 16 */

    /** Room occupancy events */
    ON_ROOM_OCCUPIED = 1 << 5, /** value 32 */

    /** Room vacancy events */
    ON_ROOM_VACATED = 1 << 6 /** value 64 */
};

/** Decode a bitmask into the webhook-status map (1 = active, 0 = inactive). */
void populateWebhookStatus(uint8_t bitmask);

/** read webhooks, thread safe */
int getWebhookStatus(Webhooks webhook);

/**
 * Dispatch an HTTPS POST webhook. Fire-and-forget requests are handed to a
 * background dispatcher thread; when waitForResponse is true the request is sent
 * synchronously on the calling thread and the HTTP status is returned.
 */
int sendHTTPSPOSTRequestFireAndForget(const std::string& baseURL, const std::string& path, const std::string& body,
                                      const std::map<std::string, std::string>& headers = {},
                                      bool waitForResponse = false);

/** Resolves the IPv4 address for `hostname` into the config snapshot being built. */
void resolveAndStoreIPAddress(UserData& ud, const std::string& hostname);

/** Stop the calling thread's webhook io_context (workers call this on shutdown). */
void stopWebhookIoContext();

/** Fire-and-forget webhooks dropped because the dispatcher queue was full. */
unsigned long long droppedWebhookCount();

/**
 * Run a blocking verification webhook on a small dedicated thread pool and invoke
 * `onDone(status)` ON A POOL THREAD when the response arrives (callers must defer
 * back to their own event loop inside the callback). Bounded: returns false when
 * the queue is full — the caller should reject the request (503) instead of
 * spawning unbounded work. Replaces the detached-thread-per-verification pattern,
 * which let a burst of private-room subscribes spawn thousands of threads each
 * potentially stuck in a multi-second connect.
 */
bool enqueueVerificationWebhook(std::string baseURL, std::string path, std::string body,
                                std::function<void(int)> onDone);
