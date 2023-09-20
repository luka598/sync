#pragma once

#include <string>
#include <vector>

namespace Bytes {

enum REPR {
  CHAR,
  HEX,
};

class Bytes {
public:
  Bytes();                                         // Empty
  Bytes(std::string s, REPR repr_type = CHAR);     // From string
  Bytes(unsigned char *begin, unsigned char *end); // From range
  Bytes(std::vector<unsigned char> v);             // From vector

  std::string repr(REPR repr_type = CHAR, std::string sep = "") const;
  size_t size() const;
  const unsigned char *c_array() const;

private:
  std::vector<unsigned char> data;
};

} // namespace Bytes
