#pragma once

#include <cstddef>
#include <string>
#include <string_view>

/** HMAC-SHA256 Constants */
constexpr int HMAC_SHA256_DIGEST_LENGTH = 32; /**< SHA-256 produces a 32-byte (256-bit) output */

/** Computes the HMAC-SHA256 of `data` under `key` into the 32-byte `output`. */
void hmac_sha256(
    const char* key, size_t key_len, const char* data, size_t data_len,
    unsigned char output[HMAC_SHA256_DIGEST_LENGTH]);

/** Converts binary data to a lowercase hex string. */
std::string to_hex(const unsigned char* data, size_t len);

/** Appends `s` to `out` as the CONTENTS of a JSON string (no surrounding quotes),
 *  escaping per RFC 8259. */
void appendJsonEscaped(std::string& out, std::string_view s);

/** Convenience wrapper returning the JSON-escaped contents of `s` (no surrounding quotes). */
std::string jsonEscape(std::string_view s);

/** Fetch the current UTC time in SQL-compatible format. */
std::string getCurrentSQLTime();

/** Constant-time equality for secrets (API keys): a naive != returns as soon as
 *  a byte differs, leaking prefix length via response timing. Length is still
 *  compared fast — only content comparison needs to be constant-time. */
bool constantTimeEquals(std::string_view a, std::string_view b);
