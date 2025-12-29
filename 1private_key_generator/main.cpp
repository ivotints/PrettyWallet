#include <array>
#include <random>
#include <iostream>
#include <iomanip>

int main() {
    std::array<uint8_t, 32> privkey;

    std::random_device rd;

    for (auto &b : privkey) {
        b = static_cast<uint8_t>(rd());
    }

    // here to check if it is in range 0 <= k <= n

    // Вывод в hex
    for (auto b : privkey) {
        std::cout << std::hex << std::setw(2)
                  << std::setfill('0') << (int)b;
    }
    std::cout << std::endl;
}
