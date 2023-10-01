#include "file.hpp"

#include "bytes.hpp"
#include <exception>
#include <filesystem>
#include <fstream>
#include <vector>

namespace file {

namespace fs = std::filesystem;

Result read_file(const std::string filename) {
  std::vector<unsigned char> buffer;

  std::ifstream file(filename, std::ios::binary);

  if (!file) {
    return {false, {}};
  }

  file.seekg(0, std::ios::end);
  std::streamsize fileSize = file.tellg();
  file.seekg(0, std::ios::beg);

  buffer.resize(static_cast<size_t>(fileSize));

  file.read(reinterpret_cast<char *>(buffer.data()), fileSize);

  file.close();

  return {true, buffer};
}

Result write_file(Bytes::Bytes data, const std::string filename,
                  bool autocreate_dir) {

  if (autocreate_dir) {
    try {
      fs::create_directories(fs::path(filename).parent_path());
    } catch (std::exception &e) {
      return {false, {}};
    }
  }

  std::ofstream file(filename, std::ios::binary);

  if (!file)
    return {false, {}};

  file.write(reinterpret_cast<const char *>(data.c_array()), data.size());

  file.close();
  return {true, {}};
}

std::vector<std::filesystem::path> get_files(std::string path) {
  std::vector<std::filesystem::path> files;
  for (const auto &entry : std::filesystem::recursive_directory_iterator(
           std::filesystem::path(path))) {
    if (entry.is_regular_file() && !entry.is_symlink())
      files.push_back(entry.path());
  }
  return files;
}

bool exists(std::string filename) {
  std::ifstream file(filename);
  return file.good();
}

} // namespace file
