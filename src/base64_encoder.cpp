#include "base64_encoder.h"

#include <cstdint>

constexpr char Base64Encoder::kEncodingTable[];
constexpr unsigned char Base64Encoder::kDecodingTable[256];

std::string Base64Encoder::encode_data(const std::vector<unsigned char>& data) {
    return encode_data(data.data(), data.size());
}

std::string Base64Encoder::encode_data(const unsigned char* data, size_t length) {
    if (length == 0) {
        return "";
    }

    size_t output_length = 4 * ((length + 2) / 3);
    std::string encoded_data;
    encoded_data.reserve(output_length);

    for (size_t i = 0; i < length; i += 3) {
        uint32_t octet_a = i < length ? data[i] : 0;
        uint32_t octet_b = i + 1 < length ? data[i + 1] : 0;
        uint32_t octet_c = i + 2 < length ? data[i + 2] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data += kEncodingTable[(triple >> 3 * 6) & 0x3F];
        encoded_data += kEncodingTable[(triple >> 2 * 6) & 0x3F];
        encoded_data += kEncodingTable[(triple >> 1 * 6) & 0x3F];
        encoded_data += kEncodingTable[(triple >> 0 * 6) & 0x3F];
    }

    size_t mod_table[] = {0, 2, 1};
    for (size_t i = 0; i < mod_table[length % 3]; i++) {
        encoded_data[encoded_data.length() - 1 - i] = '=';
    }

    return encoded_data;
}

std::vector<unsigned char> Base64Encoder::decode_data(const std::string& encoded_data) {
    return decode_data(encoded_data.c_str(), encoded_data.length());
}

std::vector<unsigned char> Base64Encoder::decode_data(const char* encoded_data, size_t length) {
    if (length == 0) {
        return {};
    }

    size_t padding = 0;
    if (length >= 2) {
        if (encoded_data[length - 1] == '=') padding++;
        if (encoded_data[length - 2] == '=') padding++;
    }

    size_t output_length = (length / 4) * 3 - padding;
    std::vector<unsigned char> decoded_data;
    decoded_data.reserve(output_length);

    for (size_t i = 0; i < length; i += 4) {
        uint32_t sextet_a = i < length ? kDecodingTable[static_cast<unsigned char>(encoded_data[i])] : 0;
        uint32_t sextet_b = i + 1 < length ? kDecodingTable[static_cast<unsigned char>(encoded_data[i + 1])] : 0;
        uint32_t sextet_c = i + 2 < length ? kDecodingTable[static_cast<unsigned char>(encoded_data[i + 2])] : 0;
        uint32_t sextet_d = i + 3 < length ? kDecodingTable[static_cast<unsigned char>(encoded_data[i + 3])] : 0;

        uint32_t triple = (sextet_a << 3 * 6) + (sextet_b << 2 * 6) + (sextet_c << 1 * 6) + (sextet_d << 0 * 6);

        decoded_data.push_back((triple >> 2 * 8) & 0xFF);

        if (i + 2 < length && encoded_data[i + 2] != '=') {
            decoded_data.push_back((triple >> 1 * 8) & 0xFF);
        }

        if (i + 3 < length && encoded_data[i + 3] != '=') {
            decoded_data.push_back((triple >> 0 * 8) & 0xFF);
        }
    }

    return decoded_data;
}
