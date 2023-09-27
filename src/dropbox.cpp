#include "dropbox.hpp"

#include <cpr/cpr.h>
#include <exception>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace dropbox {

using json = nlohmann::json;

struct Result_API {
  bool success;
  int code;
  std::shared_ptr<json> data;
};

enum class REQUEST { GET, POST };

Result_API api_request(REQUEST request_type, std::string path,
                       std::string bearer, json arguments,
                       bool log_json_parse_exception = false) {
  const std::string DROPBOX_API_BASE = "https://api.dropboxapi.com/2";

  Result_API result{true, 0, nullptr};

  cpr::Response response;
  cpr::Bearer cpr_bearer(bearer);

  if (request_type == dropbox::REQUEST::GET) {
    cpr::Parameters parameters;
    for (const auto &arg : arguments) {
      // FIXME
      /* parameters.Add({arg.first, arg.second}); */
    }
    response =
        cpr::Get(cpr::Url{DROPBOX_API_BASE + path}, cpr_bearer, parameters);

  } else if (request_type == dropbox::REQUEST::POST) {
    response = cpr::Post(cpr::Url{DROPBOX_API_BASE + path}, cpr_bearer,
                         cpr::Header{{"Content-Type", "application/json"}},
                         cpr::Body(arguments.dump()));
  }
  result.code = response.status_code;
  result.success = response.status_code >= 200 && response.status_code <= 299;

  try {
    result.data = std::make_shared<json>(json::parse(response.text));
  } catch (std::exception &e) {
    if (log_json_parse_exception) {
      std::cout << "Warning: failed to parse json" << std::endl;
      std::cout << response.url << std::endl;
      std::cout << e.what() << std::endl;
      std::cout << response.text << std::endl;
      std::cout << response.status_code << std::endl;
    }
  }

  return result;
}

Result_FileMetadata file_metadata(std::string file_path) {
  Result_FileMetadata result{false};

  Result_API api_result =
      api_request(REQUEST::POST, "/files/get_metadata", BEARER,
                  {{"include_deleted", false}, {"path", file_path}});

  if (api_result.success && api_result.data)
    result.success = true;

  return result;
}

} // namespace dropbox
