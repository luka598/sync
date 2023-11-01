#pragma once

#include "bytes.hpp"
#include <map>
#include <string>
#include <vector>

namespace sync {

class Sync {
public:
  Sync(std::string config_file_path);

  void load();
  void save();
  void hash();

private:
  std::string config_file_path;
  std::vector<bytes::Bytes> next = {};
  std::map<std::string, bytes::Bytes> files;
};

} // namespace sync
