#pragma once

#include "bytes.hpp"
#include <string>

namespace crypto {
typedef bytes::Bytes Bytes; // Not sure if this is ok

struct Result {
  bool success;
  Bytes data;
};

Result sha256(std::string input);
Result encrypt(const Bytes key, const Bytes message);
Result decrypt(const Bytes key, const Bytes c_message);
} // namespace crypto
