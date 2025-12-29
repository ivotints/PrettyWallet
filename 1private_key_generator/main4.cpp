#include <iostream>
#include <iomanip>
#include <secp256k1.h>
#include <random>
#include <cstring>

int main() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    unsigned char private_key[32];

    // Generate random private key
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 32; i++) {
        private_key[i] = dis(gen);
    }

    // Verify the private key is valid
    while (!secp256k1_ec_seckey_verify(ctx, private_key)) {
        for (int i = 0; i < 32; i++) {
            private_key[i] = dis(gen);
        }
    }

    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)private_key[i];
    }
    std::cout << std::endl;

    secp256k1_context_destroy(ctx);
    return 0;
}
