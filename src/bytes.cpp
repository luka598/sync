#include "bytes.hpp"
#include <iomanip>
#include <sstream>
#include <string>

namespace bytes {

Bytes::Bytes() : data({}) {}
Bytes::Bytes(std::string s, REPR repr_type) : data(s.begin(), s.end()) {}
Bytes::Bytes(unsigned char *begin, unsigned char *end) : data(begin, end) {}
Bytes::Bytes(std::vector<unsigned char> v) : data(v) {}

std::string Bytes::str(REPR repr_type, std::string sep) const {
  if (repr_type == REPR::CHAR) {
    return std::string(data.begin(), data.end());
  } else if (repr_type == REPR::HEX) {
    std::stringstream ss;
    for (const unsigned char &byte : data) {
      ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte << sep;
    }
    return ss.str();
  }
  return "";
}

size_t Bytes::size() const { return data.size(); }

const unsigned char *Bytes::c_array() const { return data.data(); }

} // namespace bytes
