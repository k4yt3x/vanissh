#pragma once

#include <span>
#include <string>

namespace base64 {

// Standard base64 (RFC 4648) with '=' padding
std::string encode(std::span<const unsigned char> data);

// The same without the trailing '=' padding, as used for SSH fingerprints
std::string encode_unpadded(std::span<const unsigned char> data);

}  // namespace base64
