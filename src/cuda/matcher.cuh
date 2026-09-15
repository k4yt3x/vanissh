#pragma once

// Pattern matching on the device against the base64 form of the public key
// and against its SHA-256 fingerprint. Included by the backend and by the
// unit tests: everything here, including the constant memory, is local to
// the including translation unit.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

#include <cuda_runtime.h>

#include "ed25519.cuh"
#include "vanity_pattern.h"

namespace {

constexpr int kKeyChars = static_cast<int>(kKeyTarget.length);
constexpr int kKeyFixedChars = static_cast<int>(kKeyTarget.prefix_offset);
constexpr int kFingerprintChars = static_cast<int>(kFingerprintTarget.length);
constexpr int kMaxPatternLen = kKeyChars;
constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Strings the patterns are matched against, and the parts of a pattern
enum Target : int {
    kTargetKey,
    kTargetFingerprint,
    kTargets
};
enum Kind : int {
    kKindPrefix,
    kKindSuffix,
    kKindContains,
    kKinds
};

// Search criteria encoded for the device
struct PatternTable {
    // Base64 sextet codes, [target][kind][variant][i]. Variant 1 holds the
    // alternate-case code for case-insensitive matching (same as variant 0
    // otherwise).
    uint8_t codes[kTargets][kKinds][2][kMaxPatternLen];
    int lengths[kTargets][kKinds];
    // Whether any fingerprint pattern is set; the fingerprint is only hashed then.
    int match_fingerprint;
};

__constant__ PatternTable c_patterns;

// Sextet codes of the 24 base64 characters that only depend on the 18
// constant header bytes of the blob: "AAAAC3NzaC1lZDI1NTE5AAAA".
__constant__ uint8_t c_fixed_sextets[24] = {0,  0, 0, 0,  2,  55, 13, 51, 26, 2, 53, 37,
                                            25, 3, 8, 53, 13, 19, 4,  57, 0,  0, 0,  0};

// ---------------------------------------------------------------------------
// Device code
// ---------------------------------------------------------------------------

__device__ __forceinline__ bool sextet_matches(uint8_t v, int target, int kind, int i) {
    return v == c_patterns.codes[target][kind][0][i] || v == c_patterns.codes[target][kind][1][i];
}

// Base64 sextets of N bytes: four per group of three bytes, plus two or three
// for a partial last group, as the encoder produces them before any '='.
template <int N>
__device__ __forceinline__ void to_sextets(const uint8_t bytes[N], uint8_t* sx) {
#pragma unroll
    for (int t = 0; t < N / 3; ++t) {
        const uint32_t b0 = bytes[3 * t], b1 = bytes[3 * t + 1], b2 = bytes[3 * t + 2];
        sx[4 * t] = static_cast<uint8_t>(b0 >> 2);
        sx[4 * t + 1] = static_cast<uint8_t>(((b0 & 3) << 4) | (b1 >> 4));
        sx[4 * t + 2] = static_cast<uint8_t>(((b1 & 15) << 2) | (b2 >> 6));
        sx[4 * t + 3] = static_cast<uint8_t>(b2 & 63);
    }
    constexpr int kTail = 4 * (N / 3);
    if constexpr (N % 3 == 2) {
        const uint32_t b0 = bytes[N - 2], b1 = bytes[N - 1];
        sx[kTail] = static_cast<uint8_t>(b0 >> 2);
        sx[kTail + 1] = static_cast<uint8_t>(((b0 & 3) << 4) | (b1 >> 4));
        sx[kTail + 2] = static_cast<uint8_t>((b1 & 15) << 2);
    } else if constexpr (N % 3 == 1) {
        const uint32_t b0 = bytes[N - 1];
        sx[kTail] = static_cast<uint8_t>(b0 >> 2);
        sx[kTail + 1] = static_cast<uint8_t>((b0 & 3) << 4);
    }
}

// Checks the sextets of one target string against its patterns.
__device__ __forceinline__ bool
matches_target(const uint8_t* sx, int length, int prefix_offset, int target) {
    const int prefix_len = c_patterns.lengths[target][kKindPrefix];
    for (int i = 0; i < prefix_len; ++i) {
        if (!sextet_matches(sx[prefix_offset + i], target, kKindPrefix, i)) {
            return false;
        }
    }

    const int suffix_len = c_patterns.lengths[target][kKindSuffix];
    for (int i = 0; i < suffix_len; ++i) {
        if (!sextet_matches(sx[length - suffix_len + i], target, kKindSuffix, i)) {
            return false;
        }
    }

    const int contains_len = c_patterns.lengths[target][kKindContains];
    if (contains_len > 0) {
        bool found = false;
        for (int pos = 0; pos + contains_len <= length && !found; ++pos) {
            bool ok = true;
            for (int i = 0; i < contains_len && ok; ++i) {
                ok = sextet_matches(sx[pos + i], target, kKindContains, i);
            }
            found = ok;
        }
        if (!found) {
            return false;
        }
    }

    return true;
}

// Checks the base64 form of the public key blob against the key patterns.
__device__ __forceinline__ bool matches_key(const uint32_t pk[8]) {
    // The blob is 51 bytes; the first 18 are constant and the 19th (0x20, the
    // key length) shares a base64 group with the first two key bytes.
    uint8_t sx[kKeyChars];
#pragma unroll
    for (int i = 0; i < 24; ++i) {
        sx[i] = c_fixed_sextets[i];
    }
    uint8_t bytes[33];
    bytes[0] = 0x20;
#pragma unroll
    for (int i = 0; i < 32; ++i) {
        bytes[1 + i] = static_cast<uint8_t>(pk[i >> 2] >> (8 * (i & 3)));
    }
    to_sextets<33>(bytes, sx + 24);
    return matches_target(sx, kKeyChars, kKeyFixedChars, kTargetKey);
}

// Checks the SHA-256 fingerprint of the key against the fingerprint patterns.
__device__ __forceinline__ bool matches_fingerprint(const uint32_t pk[8]) {
    uint32_t digest[8];
    ed25519::sha256_pubkey_blob(pk, digest);
    uint8_t bytes[32];
#pragma unroll
    for (int i = 0; i < 32; ++i) {
        bytes[i] = static_cast<uint8_t>(digest[i >> 2] >> (24 - 8 * (i & 3)));
    }
    uint8_t sx[kFingerprintChars];
    to_sextets<32>(bytes, sx);
    return matches_target(sx, kFingerprintChars, 0, kTargetFingerprint);
}

// The key is checked first because its sextets come for free, so with a key
// pattern the fingerprint is only hashed for the rare keys that pass.
__device__ __forceinline__ bool matches_criteria(const uint32_t pk[8]) {
    return matches_key(pk) && (!c_patterns.match_fingerprint || matches_fingerprint(pk));
}

// ---------------------------------------------------------------------------
// Host code
// ---------------------------------------------------------------------------

uint8_t base64_index(char c) {
    const char* pos = std::strchr(kBase64Alphabet, c);
    if (c == '\0' || pos == nullptr) {
        throw std::runtime_error(std::string("invalid base64 character '") + c + "'");
    }
    return static_cast<uint8_t>(pos - kBase64Alphabet);
}

// Encodes the criteria for the device; throws std::runtime_error if a pattern
// cannot be encoded or is longer than the string it is matched against.
PatternTable encode_criteria(const VanityCriteria& criteria) {
    PatternTable table{};
    const VanityPattern* patterns[kTargets] = {&criteria.key, &criteria.fingerprint};
    const VanityTarget targets[kTargets] = {kKeyTarget, kFingerprintTarget};
    for (int target = 0; target < kTargets; ++target) {
        const VanityPattern& pattern = *patterns[target];
        const std::string* parts[kKinds] = {&pattern.prefix, &pattern.suffix, &pattern.contains};
        for (int kind = 0; kind < kKinds; ++kind) {
            const std::string& part = *parts[kind];
            const size_t max_length = kind == kKindPrefix
                                          ? targets[target].length - targets[target].prefix_offset
                                          : targets[target].length;
            if (part.size() > max_length) {
                throw std::runtime_error("pattern is longer than the string it is matched against");
            }
            table.lengths[target][kind] = static_cast<int>(part.size());
            for (size_t i = 0; i < part.size(); ++i) {
                const char c = part[i];
                char alt = c;
                if (criteria.case_insensitive) {
                    if (c >= 'a' && c <= 'z') {
                        alt = static_cast<char>(c - 'a' + 'A');
                    } else if (c >= 'A' && c <= 'Z') {
                        alt = static_cast<char>(c - 'A' + 'a');
                    }
                }
                table.codes[target][kind][0][i] = base64_index(c);
                table.codes[target][kind][1][i] = base64_index(alt);
            }
        }
    }
    table.match_fingerprint = criteria.fingerprint.empty() ? 0 : 1;
    return table;
}

// Encodes the criteria and copies them to the current device
void upload_criteria(const VanityCriteria& criteria) {
    const PatternTable table = encode_criteria(criteria);
    const cudaError_t err = cudaMemcpyToSymbol(c_patterns, &table, sizeof(table));
    if (err != cudaSuccess) {
        throw std::runtime_error(
            std::string("CUDA error (cudaMemcpyToSymbol patterns): ") + cudaGetErrorString(err)
        );
    }
}

}  // namespace
