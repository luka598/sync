#include "crypto.hpp"
#include <filesystem>
#include <iostream>
#include <openssl/sha.h>

/* std::string sha256(const std::string str) { */
/*   unsigned char hash[SHA256_DIGEST_LENGTH]; */
/*   SHA256_CTX sha256; */
/*   SHA256_Init(&sha256); */
/*   SHA256_Update(&sha256, str.c_str(), str.size()); */
/*   SHA256_Final(hash, &sha256); */
/**/
/* } */

int main(int argc, char *argv[]) {
  /* for (const auto &entry : std::filesystem::recursive_directory_iterator( */
  /*          std::filesystem::path("test"))) { */
  /*   if (entry.is_regular_file()) */
  /*     std::cout << entry << std::endl; */
  /* } */
  crypto::Bytes key = crypto::string_to_bytes("TESTISI TESTISI TESTISI");
  {
    crypto::Bytes message = crypto::string_to_bytes("TESTISI TESTISI TESTISI");
    crypto::Bytes c_message = crypto::encrypt(key, message).data;
    crypto::Bytes d_message = crypto::decrypt(key, c_message).data;
    std::cout << crypto::bytes_to_hex(key) << std::endl;
    std::cout << crypto::bytes_to_hex(message) << std::endl;
    std::cout << crypto::bytes_to_hex(c_message) << std::endl;
    std::cout << crypto::bytes_to_hex(d_message) << std::endl;
  }
  std::cout << "---" << std::endl;
  {
    crypto::Bytes c_message({0x54, 0x5e, 0x68, 0x7e, 0xe5, 0x2b, 0xc5, 0x00,
                             0xe6, 0xaf, 0x93, 0xaf, 0xeb, 0xf6, 0x0a, 0xfd,
                             0x40, 0xff, 0x47, 0x54, 0x00, 0x31, 0x0e, 0x87,
                             0x8f, 0xcd, 0xeb, 0xaa, 0xe8, 0xb9, 0xf4, 0xb7,
                             0xe6, 0xdb, 0x87, 0x96, 0x90, 0xc1, 0x6d, 0xd6,
                             0xd8, 0xd9, 0xad, 0xdf, 0x63, 0xdb, 0x52, 0xa7});
    crypto::Bytes d_message = crypto::decrypt(key, c_message).data;
    std::cout << crypto::bytes_to_hex(key) << std::endl;
    std::cout << crypto::bytes_to_hex(c_message) << std::endl;
    std::cout << crypto::bytes_to_hex(d_message) << std::endl;
    std::cout << crypto::bytes_to_string(d_message) << std::endl;
  }
  return 0;
}
