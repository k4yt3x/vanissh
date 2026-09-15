#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>

// Shape of a base64 string that patterns are matched against
struct VanityTarget {
    size_t length;         // Number of characters
    size_t prefix_offset;  // Where prefixes start: constant leading characters are skipped
};

// The base64 form of an ssh-ed25519 public key blob: 68 characters, of which
// the first 25 ("AAAAC3NzaC1lZDI1NTE5AAAAI") encode the constant key type and
// length
inline constexpr VanityTarget kKeyTarget{68, 25};
// The SHA-256 fingerprint after "SHA256:": 43 characters of unpadded base64,
// the last of which encodes only four digest bits
inline constexpr VanityTarget kFingerprintTarget{43, 0};

// Matching rules for one string; every non-empty part must match
struct VanityPattern {
    std::string prefix;    // Start of the string, after the target's prefix_offset
    std::string suffix;    // End of the string
    std::string contains;  // Anywhere in the string

    [[nodiscard]] bool empty() const {
        return prefix.empty() && suffix.empty() && contains.empty();
    }

    [[nodiscard]] VanityPattern lowercased() const {
        VanityPattern result = *this;
        for (std::string* part : {&result.prefix, &result.suffix, &result.contains}) {
            std::transform(part->begin(), part->end(), part->begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
        }
        return result;
    }
};

// Search criteria: patterns for the public key and for its SHA-256
// fingerprint, all of which must match
struct VanityCriteria {
    VanityPattern key;
    VanityPattern fingerprint;
    bool case_insensitive = false;

    [[nodiscard]] bool empty() const { return key.empty() && fingerprint.empty(); }

    // Copy with every pattern lower-cased, the form the matchers expect for
    // case-insensitive search
    [[nodiscard]] VanityCriteria lowercased() const {
        VanityCriteria result = *this;
        result.key = key.lowercased();
        result.fingerprint = fingerprint.lowercased();
        return result;
    }
};
