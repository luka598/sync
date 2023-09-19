#pragma once

#include <string>
#include <vector>

namespace crypto {
typedef std::vector<unsigned char> Bytes;

struct Result {
  bool success;
  Bytes data;
};

Bytes string_to_bytes(std::string s);
std::string bytes_to_string(Bytes b);
std::string bytes_to_hex(Bytes data, std::string sep = " ");
Result sha256(std::string input);
Result encrypt(const Bytes key, const Bytes message);
Result decrypt(const Bytes key, const Bytes c_message);
} // namespace crypto
