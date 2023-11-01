#include "crypto.hpp"

#include "bytes.hpp"
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <vector>

namespace crypto
{

Result sha256(bytes::Bytes input)
{
    OpenSSL_add_all_algorithms();

    // Input data
    const char *input_data = (const char *)input.c_array(); // TODO: Get rid of the c style cast
    size_t input_length = input.size();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        return {false, {}};
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
    {
        return {false, {}};
    }

    if (EVP_DigestUpdate(mdctx, input_data, input_length) != 1)
    {
        return {false, {}};
    }

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1)
    {
        return {false, {}};
    }

    EVP_MD_CTX_free(mdctx);

    return {true, bytes::Bytes(md_value, md_value + md_len)};
}

Result encrypt(const bytes::Bytes key, const bytes::Bytes message)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char *c_message = nullptr;
    int c_message_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        return {false, {}};
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), nullptr, key.c_array(), nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {false, {}};
    }

    int len;
    c_message = new unsigned char[message.size() + AES_BLOCK_SIZE];

    if (EVP_EncryptUpdate(ctx, c_message, &len, message.c_array(), message.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        delete[] c_message;
        return {false, {}};
    }

    c_message_len = len;

    if (EVP_EncryptFinal_ex(ctx, c_message + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        delete[] c_message;
        return {false, {}};
    }
    c_message_len += len;

    EVP_CIPHER_CTX_free(ctx);

    Result result{true, bytes::Bytes(c_message, c_message + c_message_len)};
    delete[] c_message;

    return result;
}

Result decrypt(const bytes::Bytes key, const bytes::Bytes c_message)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char *message = nullptr;
    int message_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        return {false, {}};
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), nullptr, key.c_array(), nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return {false, {}};
    }

    int len;
    message = new unsigned char[c_message.size()];

    if (EVP_DecryptUpdate(ctx, message, &len, c_message.c_array(), c_message.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        delete[] message;
        return {false, {}};
    }
    message_len = len;

    if (EVP_DecryptFinal_ex(ctx, message + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        delete[] message;
        return {false, {}};
    }
    message_len += len;

    EVP_CIPHER_CTX_free(ctx);

    Result result{true, bytes::Bytes(message, message + message_len)};
    delete[] message;

    return result;
}

} // namespace crypto
