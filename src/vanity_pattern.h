#pragma once

#include <algorithm>
#include <cctype>
#include <string>

// Search criteria for the base64 form of an ssh-ed25519 public key
struct VanityPattern {
    std::string prefix;    // Start of the variable part, after the constant 25 characters
    std::string suffix;    // End of the key
    std::string contains;  // Anywhere in the key
    bool case_insensitive = false;

    [[nodiscard]] bool empty() const {
        return prefix.empty() && suffix.empty() && contains.empty();
    }

    // Copy with every part lower-cased, the form the matchers expect for
    // case-insensitive search
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
