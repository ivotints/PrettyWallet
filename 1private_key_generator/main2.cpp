// g++ main2.cpp -lsecp256k1 && ./a.out

#include <secp256k1.h>
#include <sys/random.h>
#include <iostream>
#include <iomanip>
#include <cstring>

int main() {
    int i = 0;
    while (i++ < 1'000'000) {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        unsigned char seckey[32];

        do {
            if (getrandom(seckey, sizeof(seckey), 0) != sizeof(seckey)) {
                std::cerr << "RNG error\n";
                return 1;
            }
        } while (!secp256k1_ec_seckey_verify(ctx, seckey));

        for (auto b : seckey) {
            std::cout << std::hex << std::setw(2)
            << std::setfill('0') << (int)b;
        }
        std::cout << "\n";
    }
}
