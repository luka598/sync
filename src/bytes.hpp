#pragma once

#include <string>
#include <vector>

namespace bytes
{

enum REPR
{
    CHAR,
    HEX,
};

// TODO: Change unsigned char to uint8_t
class Bytes
{
  public:
    Bytes();                                         // Empty
    Bytes(std::string s, REPR repr_type = CHAR);     // From string
    Bytes(unsigned char *begin, unsigned char *end); // From range
    Bytes(std::vector<unsigned char> v);             // From vector

    std::string str(REPR repr_type = CHAR, std::string sep = "") const;
    size_t size() const;
    const unsigned char *c_array() const;

  private:
    std::vector<unsigned char> data;
};

} // namespace bytes
