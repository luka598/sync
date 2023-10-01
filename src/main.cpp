#include "bytes.hpp"
#include "cpr/bearer.h"
#include "cpr/parameters.h"
#include "crypto.hpp"
#include "dropbox.hpp"
#include "file.hpp"

#include <filesystem>
#include <iostream>
int main() {
  std::cout << std::boolalpha;
  /* dropbox::Dropbox dbx(".secret.config"); */
  /* std::cout << dbx.download("/data/test1").success << std::endl; */
  /* std::cout << dbx.download("/data/test1").data.repr(Bytes::REPR::HEX, " ")
   */
  /*           << std::endl; */
  /* std::cout */
  /*     << dbx.upload("/data/test2.txt", Bytes::Bytes("UPLOAD TEST")).success
   */
  /*     << std::endl; */
  std::cout << file::write_file(Bytes::Bytes("DATA!!!\n"), "test_dir/test_file")
                   .success
            << std::endl;
  return 0;
}
