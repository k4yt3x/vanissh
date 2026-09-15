#include "base64_encoder.h"

#include <cstdint>

namespace base64 {

namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

}  // namespace

std::string encode(std::span<const unsigned char> data) {
    std::string encoded;
    encoded.reserve(4 * ((data.size() + 2) / 3));

    size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        const uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                                (static_cast<uint32_t>(data[i + 1]) << 8) | data[i + 2];
        encoded += kAlphabet[(triple >> 18) & 0x3F];
        encoded += kAlphabet[(triple >> 12) & 0x3F];
        encoded += kAlphabet[(triple >> 6) & 0x3F];
        encoded += kAlphabet[triple & 0x3F];
    }

    const size_t remaining = data.size() - i;
    if (remaining > 0) {
        const uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                                (remaining > 1 ? static_cast<uint32_t>(data[i + 1]) << 8 : 0u);
        encoded += kAlphabet[(triple >> 18) & 0x3F];
        encoded += kAlphabet[(triple >> 12) & 0x3F];
        encoded += remaining > 1 ? kAlphabet[(triple >> 6) & 0x3F] : '=';
        encoded += '=';
    }

    return encoded;
}

std::string encode_unpadded(std::span<const unsigned char> data) {
    std::string encoded = encode(data);
    while (!encoded.empty() && encoded.back() == '=') {
        encoded.pop_back();
    }
    return encoded;
}

}  // namespace base64
