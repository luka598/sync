#pragma once

#include "bytes.hpp"
#include <string>

namespace dropbox {
const std::string DROPBOX_API_BASE = "https://api.dropboxapi.com/2";
const std::string DROPBOX_CONTENT_BASE = "https://content.dropboxapi.com/2";

struct File_metadata {
  bool success;
};

struct Download {
  bool success;
  Bytes::Bytes data;
};

struct Upload {
  bool success;
};

class Dropbox {
public:
  Dropbox(std::string config_file);
  File_metadata file_metadata(std::string file_path);
  Download download(std::string file_path);
  Upload upload(std::string file_path, Bytes::Bytes data);

private:
  std::string app_key;
  std::string app_secret;
  std::string access_token;
  std::string refresh_token;
  std::string config_file;

  void init_auth();
  void refresh();
  void load_config();
  void save_config();
};

} // namespace dropbox
