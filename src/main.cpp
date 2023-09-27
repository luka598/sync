#include "bytes.hpp"
#include "cpr/bearer.h"
#include "cpr/parameters.h"
#include "crypto.hpp"
#include "dropbox.hpp"
#include "file.hpp"

#include <filesystem>
#include <iostream>
int main() {
  dropbox::Result_FileMetadata r = dropbox::file_metadata("/data/test");
  std::cout << r.success << std::endl;
  return 0;
}
