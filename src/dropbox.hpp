#pragma once

#include "secrets.hpp"

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <string>

namespace dropbox {
const std::string BEARER = DROPBOX_BEARER;

struct Result_FileMetadata {
  bool success;
};
Result_FileMetadata file_metadata(std::string file_path);
} // namespace dropbox
