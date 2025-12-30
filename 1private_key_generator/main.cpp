/*
g++ main.cpp PrivateKeyGenerator.cpp -Ofast && time ./a.out
*/

#include "PrivateKeyGenerator.hpp"
#include <iostream>
#include <iomanip>
#include <cstdint>

static volatile uint64_t blackhole = 0;

int main()
{
    PrivateKeyGenerator gen;

    for (int i = 0; i < 1'000'000'000; ++i)
    {
        uint64_t key[4];
        gen.generate_into(key);
        for (auto v : key) blackhole ^= v;
    }

    std::cout << std::hex << blackhole << std::endl;
    return 0;
}
