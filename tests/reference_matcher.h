#pragma once

// Independent reference for the vanity matchers, used by the CPU and GPU
// differential tests: plain string operations on the base64 strings, sharing
// no code with the implementations under test. Host-only, C++17.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>

#include <openssl/evp.h>

#include "vanity_pattern.h"

namespace reference {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr size_t kKeyLength = 68;
constexpr size_t kKeyPrefixOffset = 25;
constexpr size_t kFingerprintLength = 43;

inline std::string base64(const uint8_t* data, size_t size, bool pad) {
    std::string out;
    size_t i = 0;
    for (; i + 3 <= size; i += 3) {
        const uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out += kAlphabet[v >> 18];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        out += kAlphabet[v & 63];
    }
    if (size - i == 2) {
        const uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out += kAlphabet[v >> 18];
        out += kAlphabet[(v >> 12) & 63];
        out += kAlphabet[(v >> 6) & 63];
        if (pad) {
            out += '=';
        }
    } else if (size - i == 1) {
        const uint32_t v = uint32_t(data[i]) << 16;
        out += kAlphabet[v >> 18];
        out += kAlphabet[(v >> 12) & 63];
        if (pad) {
            out += "==";
        }
    }
    return out;
}

// The 51-byte ssh-ed25519 public key blob
inline void key_blob(const uint8_t pk[32], uint8_t blob[51]) {
    const uint8_t header[19] = {
        0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32
    };
    std::memcpy(blob, header, 19);
    std::memcpy(blob + 19, pk, 32);
}

// The 68-character base64 form of the public key blob
inline std::string key_string(const uint8_t pk[32]) {
    uint8_t blob[51];
    key_blob(pk, blob);
    return base64(blob, 51, true);
}

// The 43-character SHA-256 fingerprint without "SHA256:"
inline std::string fingerprint_string(const uint8_t pk[32]) {
    uint8_t blob[51];
    key_blob(pk, blob);
    uint8_t digest[32];
    unsigned int length = 0;
    EVP_Digest(blob, 51, digest, &length, EVP_sha256(), nullptr);
    return base64(digest, 32, false);
}

inline std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

inline bool matches_pattern(
    const std::string& text,
    size_t prefix_offset,
    const VanityPattern& pattern,
    bool case_insensitive
) {
    const std::string t = case_insensitive ? lower(text) : text;
    const std::string prefix = case_insensitive ? lower(pattern.prefix) : pattern.prefix;
    const std::string suffix = case_insensitive ? lower(pattern.suffix) : pattern.suffix;
    const std::string contains = case_insensitive ? lower(pattern.contains) : pattern.contains;
    if (!prefix.empty()) {
        if (t.size() < prefix_offset + prefix.size() ||
            t.compare(prefix_offset, prefix.size(), prefix) != 0) {
            return false;
        }
    }
    if (!suffix.empty()) {
        if (t.size() < suffix.size() ||
            t.compare(t.size() - suffix.size(), suffix.size(), suffix) != 0) {
            return false;
        }
    }
    if (!contains.empty() && t.find(contains) == std::string::npos) {
        return false;
    }
    return true;
}

// Whether a key with the given base64 form and fingerprint matches the criteria
inline bool
matches(const std::string& key, const std::string& fingerprint, const VanityCriteria& criteria) {
    return matches_pattern(key, kKeyPrefixOffset, criteria.key, criteria.case_insensitive) &&
           matches_pattern(fingerprint, 0, criteria.fingerprint, criteria.case_insensitive);
}

inline std::string random_base64(std::mt19937_64& rng, size_t length) {
    std::string s;
    for (size_t i = 0; i < length; ++i) {
        s += kAlphabet[rng() % 64];
    }
    return s;
}

// Random pattern for one target, drawn from `text` so that it can match:
// exact substrings (positives), substrings with one character changed or
// shifted by one position (near misses), and random strings (negatives).
// Letters are randomly re-cased when case_insensitive.
inline VanityPattern random_pattern(
    std::mt19937_64& rng,
    const std::string& text,
    size_t prefix_offset,
    bool case_insensitive
) {
    VanityPattern pattern;
    const uint64_t kinds = 1 + rng() % 7;  // bit 0: prefix, 1: suffix, 2: contains
    for (int kind = 0; kind < 3; ++kind) {
        if (!(kinds & (1u << kind))) {
            continue;
        }
        const size_t max_length = kind == 0 ? text.size() - prefix_offset : text.size();
        size_t length = 1 + rng() % 4;
        const uint64_t roll = rng() % 100;
        if (roll < 5) {
            length = max_length;
        } else if (roll < 15) {
            length = 1 + rng() % max_length;
        }

        std::string part;
        const uint64_t mode = rng() % 100;
        if (mode < 35) {
            part = random_base64(rng, length);
        } else {
            size_t pos = kind == 0   ? prefix_offset
                         : kind == 1 ? text.size() - length
                                     : rng() % (text.size() - length + 1);
            if (mode < 50 && kind != 2) {
                // Shifted by one position: a prefix or suffix that is off by one
                if (kind == 0 && pos + 1 + length <= text.size()) {
                    pos += 1;
                } else if (kind == 1 && pos > 0) {
                    pos -= 1;
                }
            }
            part = text.substr(pos, length);
            if (mode >= 50 && mode < 70) {
                // One character changed
                char& c = part[rng() % part.size()];
                char replacement = c;
                while (replacement == c) {
                    replacement = kAlphabet[rng() % 64];
                }
                c = replacement;
            }
        }
        if (case_insensitive) {
            for (char& c : part) {
                if (rng() % 2 == 0) {
                    if (c >= 'a' && c <= 'z') {
                        c = static_cast<char>(c - 'a' + 'A');
                    } else if (c >= 'A' && c <= 'Z') {
                        c = static_cast<char>(c - 'A' + 'a');
                    }
                }
            }
        }
        (kind == 0 ? pattern.prefix : kind == 1 ? pattern.suffix : pattern.contains) = part;
    }
    return pattern;
}

// Random criteria over the key and/or fingerprint strings of one key
inline VanityCriteria
random_criteria(std::mt19937_64& rng, const std::string& key, const std::string& fingerprint) {
    VanityCriteria criteria;
    criteria.case_insensitive = rng() % 2 == 0;
    const uint64_t targets = 1 + rng() % 3;  // bit 0: key, 1: fingerprint
    if (targets & 1) {
        criteria.key = random_pattern(rng, key, kKeyPrefixOffset, criteria.case_insensitive);
    }
    if (targets & 2) {
        criteria.fingerprint = random_pattern(rng, fingerprint, 0, criteria.case_insensitive);
    }
    return criteria;
}

inline std::string describe(const VanityCriteria& c) {
    return "key{prefix=" + c.key.prefix + " suffix=" + c.key.suffix +
           " contains=" + c.key.contains + "} fingerprint{prefix=" + c.fingerprint.prefix +
           " suffix=" + c.fingerprint.suffix + " contains=" + c.fingerprint.contains + "}" +
           (c.case_insensitive ? " ignore-case" : "");
}

}  // namespace reference
