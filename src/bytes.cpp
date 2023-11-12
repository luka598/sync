#include "bytes.hpp"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>

namespace bytes
{

static const std::map<char, Bytes::Byte> hex_map = {{'0', 0},  {'1', 1},  {'2', 2},  {'3', 3}, {'4', 4},  {'5', 5},
                                                    {'6', 6},  {'7', 7},  {'8', 8},  {'9', 9}, {'a', 10}, {'b', 11},
                                                    {'c', 12}, {'d', 13}, {'e', 14}, {'f', 15}};

Bytes::Bytes() : data({})
{
}
Bytes::Bytes(std::string s, REPR repr_type)
{
    if (repr_type == REPR::CHAR)
    {
        data = Container(s.begin(), s.end());
    }
    else if (repr_type == REPR::HEX)
    {
        if (s.length() % 2 == 1)
            throw std::runtime_error("Provided string is not a hex value");

        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
        for (size_t i = 0; i < s.length(); i += 2)
        {
            Byte byte = 0;
            byte += hex_map.at(s.at(i)) * 16;
            byte += hex_map.at(s.at(i + 1));
            data.push_back(byte);
        }
    }
}
Bytes::Bytes(unsigned char *begin, unsigned char *end) : data(begin, end)
{
}
Bytes::Bytes(std::vector<unsigned char> v) : data(v)
{
}

std::string Bytes::str(REPR repr_type, std::string sep) const
{
    if (repr_type == REPR::CHAR)
    {
        return std::string(data.begin(), data.end());
    }
    else if (repr_type == REPR::HEX)
    {
        std::stringstream ss;
        for (const unsigned char &byte : data)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte << sep;
        }
        return ss.str();
    }
    return "";
}
std::string Bytes::hex(std::string sep) const
{
    return str(bytes::REPR::HEX, sep);
}

size_t Bytes::size() const
{
    return data.size();
}

const unsigned char *Bytes::c_array() const
{
    return data.data();
}

const std::vector<unsigned char> &Bytes::vec() const
{
    return data;
}

Bytes Bytes::operator+(const Bytes &other) const
{
    return Bytes::merge(*this, other);
}
bool Bytes::operator<(const Bytes &other) const
{
    for (size_t i = 0; i < std::min(size(), other.size()); i++)
    {
        int diff = vec()[i] - other.vec()[i];
        if (diff < 0)
        {
            return true;
        }
        else if (diff == 0)
        {
            continue;
        }
        else
        {
            return false;
        }
    }
    return false;
}
bool Bytes::operator==(const Bytes &other) const
{
    return data == other.data;
}

std::ostream &operator<<(std::ostream &os, const Bytes &obj)
{
    os << "Bytes(" << obj.hex() << ")";
    return os;
}

Bytes Bytes::merge(Bytes a, Bytes b)
{
    std::vector<unsigned char> merged;
    merged.insert(merged.end(), a.vec().begin(), a.vec().end());
    merged.insert(merged.end(), b.vec().begin(), b.vec().end());
    return Bytes(merged);
}

} // namespace bytes
