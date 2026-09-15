#pragma once

#include <span>
#include <string>

namespace base64 {

// Standard base64 (RFC 4648) with '=' padding
std::string encode(std::span<const unsigned char> data);

}  // namespace base64
