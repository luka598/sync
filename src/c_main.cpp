#include "bytes.hpp"
#include "crypto.hpp"
#include <iostream>
#include <openssl/sha.h>

int main(int argc, char *argv[])
{

    bytes::Bytes key = bytes::Bytes("TESTISI TESTISI TESTISI");
    {
        bytes::Bytes message = bytes::Bytes("TESTISI TESTISI TESTISI");
        bytes::Bytes c_message = crypto::encrypt(key, message).data;
        bytes::Bytes d_message = crypto::decrypt(key, c_message).data;
        std::cout << key.str(bytes::REPR::HEX, " ") << std::endl;
        std::cout << message.str(bytes::REPR::HEX, " ") << std::endl;
        std::cout << c_message.str(bytes::REPR::HEX, " ") << std::endl;
        std::cout << d_message.str(bytes::REPR::HEX, " ") << std::endl;
    }
    std::cout << "---" << std::endl;
    {
        bytes::Bytes c_message(std::vector<unsigned char>{
            0x54, 0x5e, 0x68, 0x7e, 0xe5, 0x2b, 0xc5, 0x00, 0xe6, 0xaf, 0x93, 0xaf, 0xeb, 0xf6, 0x0a, 0xfd,
            0x40, 0xff, 0x47, 0x54, 0x00, 0x31, 0x0e, 0x87, 0x8f, 0xcd, 0xeb, 0xaa, 0xe8, 0xb9, 0xf4, 0xb7,
            0xe6, 0xdb, 0x87, 0x96, 0x90, 0xc1, 0x6d, 0xd6, 0xd8, 0xd9, 0xad, 0xdf, 0x63, 0xdb, 0x52, 0xa7});
        bytes::Bytes d_message = crypto::decrypt(key, c_message).data;
        std::cout << key.str(bytes::REPR::HEX, " ") << std::endl;
        std::cout << c_message.str(bytes::REPR::HEX, " ") << std::endl;
        std::cout << d_message.str(bytes::REPR::HEX, " ") << std::endl;
        std::cout << d_message.str() << std::endl;
    }
    return 0;
}
