#include "Util.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <chrono>
#include <ctime>

bool constantTimeEquals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

/** Computes the HMAC-SHA256 of `data` under `key` into the 32-byte `output`. */
void hmac_sha256(
    const char* key, size_t key_len, const char* data, size_t data_len,
    unsigned char output[HMAC_SHA256_DIGEST_LENGTH]) {
    HMAC_CTX* ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), nullptr);
    HMAC_Update(ctx, (unsigned char*)data, data_len);

    unsigned int out_len = 0;
    HMAC_Final(ctx, output, &out_len);

    HMAC_CTX_free(ctx);
}

/** Converts binary data to a lowercase hex string. */
std::string to_hex(const unsigned char* data, size_t len) {
    static const char hex_digits[] = "0123456789abcdef";

    std::string hex(len * 2, ' ');
    for (size_t i = 0; i < len; ++i) {
        hex[2 * i] = hex_digits[(data[i] >> 4) & 0xF];
        hex[2 * i + 1] = hex_digits[data[i] & 0xF];
    }

    return hex;
}

/**
 * Appends `s` to `out` as the CONTENTS of a JSON string (without surrounding quotes),
 * escaping per RFC 8259. All server envelopes and webhook payloads are built by
 * concatenating raw strings, so any user-controlled field (message, rid, uid, metadata)
 * containing a '"', '\\', or control character would otherwise break out of its JSON
 * string and corrupt the envelope (or inject fields). This makes that impossible.
 */
void appendJsonEscaped(std::string& out, std::string_view s) {
    static const char hex_digits[] = "0123456789abcdef";
    for (unsigned char c : s) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20) {
                    /** Other control characters must be escaped as \u00XX */
                    out += "\\u00";
                    out += hex_digits[(c >> 4) & 0xF];
                    out += hex_digits[c & 0xF];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
}

/** Convenience wrapper returning the JSON-escaped contents of `s` (no surrounding quotes). */
std::string jsonEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    appendJsonEscaped(out, s);
    return out;
}

/** Fetch the current UTC time in SQL-compatible format. */
std::string getCurrentSQLTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    /** gmtime_r (not gmtime) because gmtime returns a shared static buffer and is not thread-safe. */
    std::tm tm;
    gmtime_r(&now_c, &tm);

    char buffer[20]; /** 'YYYY-MM-DD HH:MM:SS' format */

    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);

    return std::string(buffer);
}
