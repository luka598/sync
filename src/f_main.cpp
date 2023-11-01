#include "bytes.hpp"
#include "crypto.hpp"
#include "file.hpp"
#include <filesystem>
#include <iostream>

int main(int argc, char *argv[])
{
    for (std::filesystem::path p : file::get_files("test"))
    {
        std::cout << p.generic_string() << std::endl;
        std::cout << file::read_file(p.native()).data.str(bytes::HEX, " ") << std::endl;
    }
    return 0;
}
