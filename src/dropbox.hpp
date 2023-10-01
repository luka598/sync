#pragma once

#include <string>

namespace dropbox {
const std::string DROPBOX_API_BASE = "https://api.dropboxapi.com/2";

struct File_metadata {
  bool success;
};

class Dropbox {
public:
  Dropbox(std::string config_file);
  File_metadata file_metadata(std::string file_path);

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
