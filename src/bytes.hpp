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
    typedef unsigned char Byte;
    typedef std::vector<Byte> Container;

    Bytes();                                         // Empty
    Bytes(std::string s, REPR repr_type = CHAR);     // From string
    Bytes(unsigned char *begin, unsigned char *end); // From range
    Bytes(std::vector<unsigned char> v);             // From vector

    std::string str(REPR repr_type = CHAR, std::string sep = "") const;
    std::string hex(std::string sep = "") const;
    size_t size() const;
    const unsigned char *c_array() const;
    const std::vector<unsigned char> &vec() const;

    Bytes operator+(const Bytes &other) const;
    bool operator<(const Bytes &other) const;
    bool operator==(const Bytes &other) const;

    friend std::ostream &operator<<(std::ostream &os, const Bytes &obj);

    static Bytes merge(const Bytes a, const Bytes b);

  private:
    Container data;
};

} // namespace bytes
