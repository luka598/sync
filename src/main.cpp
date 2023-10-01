#include "bytes.hpp"
#include "cpr/bearer.h"
#include "cpr/parameters.h"
#include "crypto.hpp"
#include "dropbox.hpp"
#include "file.hpp"

#include <filesystem>
#include <iostream>
int main() {
  dropbox::Dropbox dbx(".secret.config");
  std::cout << dbx.file_metadata("/data/test").success << std::endl;
  return 0;
}
