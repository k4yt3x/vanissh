#pragma once

#include <cstdint>
#include <string>

// Group non-negative display values with commas, regardless of the system locale.
inline std::string format_number(uint64_t value) {
    std::string text = std::to_string(value);
    for (size_t pos = text.size(); pos > 3; pos -= 3) {
        text.insert(pos - 3, 1, ',');
    }
    return text;
}
