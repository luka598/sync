#include "dropbox.hpp"
#include "bytes.hpp"
#include "file.hpp"

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

enum class HTTP_METHOD { GET, POST };
enum class CONTENT_TYPE { APPLICATION_JSON, APPLICATION_OCTET_STREAM };

class Request {
public:
  // Request parameters
  std::string url;
  HTTP_METHOD method;
  std::map<std::string, std::string> header;
  std::map<std::string, std::string> parameters;
  std::map<std::string, std::string> payload;
  bytes::Bytes body;
  // Response
  cpr::Response _cpr_response;
  long status_code = -1;
  bool success = false;
  bytes::Bytes result;

  Request(std::string url, HTTP_METHOD method) : url(url), method(method) {}

  void set_content_type(CONTENT_TYPE content_type) {
    if (content_type == CONTENT_TYPE::APPLICATION_JSON) {
      header.insert({"Content-type", "application/json"});
    } else if (content_type == CONTENT_TYPE::APPLICATION_OCTET_STREAM) {
      header.insert({"Content-type", "application/octet-stream"});
    }
  }

  void add_bearer(std::string bearer) {
    header.insert({"Authorization", "Bearer " + bearer});
  }

  void add_json(json data) {
    set_content_type(CONTENT_TYPE::APPLICATION_JSON);
    body = bytes::Bytes(data.dump());
  }

  void send() {
    cpr::Url cpr_url{url};

    cpr::Header cpr_header;
    for (auto const &pair : header) {
      cpr_header.insert(pair);
    }

    cpr::Parameters cpr_parameters;
    for (auto const &pair : parameters) {
      cpr_parameters.Add({pair.first, pair.second});
    }

    cpr::Payload cpr_payload{};
    for (auto const &pair : payload) {
      cpr_payload.Add({pair.first, pair.second});
    }

    cpr::Body cpr_body{body.repr()};

    if (method == HTTP_METHOD::GET) {
      _cpr_response = cpr::Get(cpr_url, cpr_header, cpr_parameters);
    } else if (method == HTTP_METHOD::POST) {
      if (payload.size() > 0) {
        _cpr_response =
            cpr::Post(cpr_url, cpr_header, cpr_parameters, cpr_payload);
      } else {
        _cpr_response =
            cpr::Post(cpr_url, cpr_header, cpr_parameters, cpr_body);
      }
    }

    status_code = _cpr_response.status_code;
    success =
        _cpr_response.status_code >= 200 && _cpr_response.status_code <= 299;
    result = bytes::Bytes(_cpr_response.text);
  }

  std::unique_ptr<json> res_as_json() {
    try {
      return std::make_unique<json>(json::parse(result.repr()));
    } catch (std::exception &e) {
      return std::make_unique<json>(nullptr);
    }
  }
};

File_metadata Dropbox::file_metadata(std::string file_path) {
  Request r(DROPBOX_API_BASE + "/files/get_metadata", HTTP_METHOD::POST);
  r.add_bearer(access_token);
  r.add_json({{"include_deleted", false}, {"path", file_path}});
  r.send();
  if (r.success && r.res_as_json()) {
    return {true};
  } else {
    return {false};
  }
}

Download Dropbox::download(std::string file_path) {
  Request r(DROPBOX_CONTENT_BASE + "/files/download", HTTP_METHOD::POST);
  r.set_content_type(CONTENT_TYPE::APPLICATION_OCTET_STREAM);
  r.add_bearer(access_token);
  r.header.insert({"Dropbox-API-Arg", json{{"path", file_path}}.dump()});
  r.send();
  if (r.success) {
    return {true, r.result};
  } else {
    return {false, {}};
  }
}

Upload Dropbox::upload(std::string file_path, bytes::Bytes data) {
  Request r(DROPBOX_CONTENT_BASE + "/files/upload", HTTP_METHOD::POST);
  r.set_content_type(CONTENT_TYPE::APPLICATION_OCTET_STREAM);
  r.add_bearer(access_token);
  r.header.insert({"Dropbox-API-Arg", json{{"autorename", false},
                                           {"mode", "add"},
                                           {"mute", false},
                                           {"path", file_path},
                                           {"strict_conflict", false}}
                                          .dump()});
  r.body = data;
  r.send();
  if (r.success) {
    return {true};
  } else {
    return {false};
  }
}

Dropbox::Dropbox(std::string config_file) : config_file(config_file) {
  if (file::exists(config_file)) {
    load_config();
    refresh();
  } else {
    init_auth();
  }
  return;
}
void Dropbox::init_auth() {
  std::string authorization_code;

  std::cout << "Enter app key: ";
  std::cout << std::endl;
  std::cin >> app_key;
  std::cout << std::endl;

  std::cout << "Enter app secret: ";
  std::cout << std::endl;
  std::cin >> app_secret;
  std::cout << std::endl;

  std::cout << "Authorize this app: ";
  std::cout << "https://www.dropbox.com/oauth2/authorize";
  std::cout << "?client_id=" << app_key;
  std::cout << "&response_type=code&token_access_type=offline";
  std::cout << std::endl;
  std::cin >> authorization_code;

  cpr::Response response =
      cpr::Post(cpr::Url{"https://api.dropboxapi.com/oauth2/token"},
                cpr::Parameters{{"code", authorization_code},
                                {"grant_type", "authorization_code"},
                                {"client_id", app_key},
                                {"client_secret", app_secret}});

  try {
    json data = json::parse(response.text);
    access_token = data["access_token"];
    refresh_token = data["refresh_token"];
  } catch (std::exception &e) {
    throw std::runtime_error("Exception while parsing json!");
  }
}
void Dropbox::refresh() {
  cpr::Response response =
      cpr::Post(cpr::Url{"https://api.dropboxapi.com/oauth2/token"},
                cpr::Parameters{{"grant_type", "refresh_token"},
                                {"refresh_token", refresh_token},
                                {"client_id", app_key},
                                {"client_secret", app_secret}});

  try {
    json data = json::parse(response.text);
    access_token = data["access_token"];
  } catch (std::exception &e) {
    std::cout << response.text << std::endl;
    std::cout << e.what() << std::endl;
    throw std::runtime_error("Exception while parsing json!");
  }
}
void Dropbox::load_config() {
  file::Result f = file::read_file(config_file);
  if (!f.success)
    throw std::runtime_error("Error while reading config file.");
  try {
    json config = json::parse(
        f.data.repr()); // HACK: Using repr is kind of a hack but idk for now
    app_key = config["app_key"];
    app_secret = config["app_secret"];
    refresh_token = config["refresh_token"];
  } catch (std::exception &e) {
    std::cout << e.what() << std::endl;
    throw std::runtime_error("Exception while parsing json!");
  }
}
void Dropbox::save_config() {
  json config = {{"app_key", app_key},
                 {"app_secret", app_secret},
                 {"refresh_token", refresh_token}};
  bytes::Bytes data(config.dump());
  file::write_file(data, config_file);
}

} // namespace dropbox
