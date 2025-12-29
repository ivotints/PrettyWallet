// g++ main5.cpp -lssl -lcrypto  && ./a.out

#include <openssl/rand.h>
#include <iostream>
#include <iomanip>

int main() {
    unsigned char private_key[32];

    if (RAND_bytes(private_key, 32) != 1) {
        std::cerr << "Error generating random bytes" << std::endl;
        return 1;
    }

    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)private_key[i];
    }
    std::cout << std::endl;

    return 0;
}
