#include <iostream>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>

std::string generatePrivateKey() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned long long> dis;

    std::stringstream ss;

    // Generate 32 bytes (256 bits) for the private key
    for (int i = 0; i < 4; i++) {
        unsigned long long random_value = dis(gen);
        ss << std::hex << std::setfill('0') << std::setw(16) << random_value;
    }

    return ss.str();
}

int main() {
    std::string privateKey = generatePrivateKey();
    std::cout << "Generated Ethereum Private Key:" << std::endl;
    std::cout << privateKey << std::endl;
    return 0;
}
