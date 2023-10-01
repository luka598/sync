#pragma once

#include "bytes.hpp"
#include <filesystem>
#include <fstream>
#include <vector>

namespace file {
struct Result {
  bool success;
  Bytes::Bytes data;
};

Result read_file(const std::string filename);
Result write_file(Bytes::Bytes data, const std::string filename,
                  bool autocreate_dir = true);
std::vector<std::filesystem::path> get_files(std::string path);
bool exists(std::string filename);

} // namespace file
