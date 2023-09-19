#include "crypto.hpp"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <vector>

namespace crypto {
Bytes string_to_bytes(std::string s) { return Bytes(s.begin(), s.end()); }
std::string bytes_to_string(Bytes b) { return std::string(b.begin(), b.end()); }
std::string bytes_to_hex(const Bytes data, std::string sep) {
  std::stringstream ss;
  for (const unsigned char &byte : data) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte << sep;
  }
  return ss.str();
}

Result sha256(std::string input) {
  OpenSSL_add_all_algorithms();

  // Input data
  const char *input_data = input.c_str();
  size_t input_length = input.length();

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    return {false, {}};
  }

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
    return {false, {}};
  }

  if (EVP_DigestUpdate(mdctx, input_data, input_length) != 1) {
    return {false, {}};
  }

  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
    return {false, {}};
  }

  EVP_MD_CTX_free(mdctx);

  return {true, std::vector<unsigned char>(md_value, md_value + md_len)};
}

Result encrypt(const std::vector<unsigned char> key,
               const std::vector<unsigned char> message) {
  EVP_CIPHER_CTX *ctx;
  unsigned char *c_message = nullptr;
  int c_message_len;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    return {false, {}};
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), nullptr, key.data(),
                         nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {false, {}};
  }

  int len;
  c_message = new unsigned char[message.size() + AES_BLOCK_SIZE];

  if (EVP_EncryptUpdate(ctx, c_message, &len, message.data(), message.size()) !=
      1) {
    EVP_CIPHER_CTX_free(ctx);
    delete[] c_message;
    return {false, {}};
  }

  c_message_len = len;

  if (EVP_EncryptFinal_ex(ctx, c_message + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    delete[] c_message;
    return {false, {}};
  }
  c_message_len += len;

  EVP_CIPHER_CTX_free(ctx);

  Result result{
      true, std::vector<unsigned char>(c_message, c_message + c_message_len)};
  delete[] c_message;

  return result;
}

Result decrypt(const Bytes key, const Bytes c_message) {
  EVP_CIPHER_CTX *ctx;
  unsigned char *message = nullptr;
  int message_len;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    return {false, {}};
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), nullptr, key.data(),
                         nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {false, {}};
  }

  int len;
  message = new unsigned char[c_message.size()];

  if (EVP_DecryptUpdate(ctx, message, &len, c_message.data(),
                        c_message.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    delete[] message;
    return {false, {}};
  }
  message_len = len;

  if (EVP_DecryptFinal_ex(ctx, message + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    delete[] message;
    return {false, {}};
  }
  message_len += len;

  EVP_CIPHER_CTX_free(ctx);

  Result result{true, Bytes(message, message + message_len)};
  delete[] message;

  return result;
}

} // namespace crypto
