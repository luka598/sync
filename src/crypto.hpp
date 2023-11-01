#pragma once

#include "bytes.hpp"
#include <string>

namespace crypto
{

struct Result
{
    bool success;
    bytes::Bytes data;
};

Result sha256(std::string input);
Result encrypt(const bytes::Bytes key, const bytes::Bytes message);
Result decrypt(const bytes::Bytes key, const bytes::Bytes c_message);
} // namespace crypto
