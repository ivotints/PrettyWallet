/*
g++ test.cpp -Ofast && time ./a.out
*/

#include <array>
#include <random>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>

static volatile uint64_t blackhole = 0;

int main()
{
    uint64_t private_key[4];

    std::random_device rd;
    std::seed_seq seq{rd(), rd(), rd(), rd()};
    std::mt19937_64 rng(seq);

    for (int i = 0; i < 1'000'000'000; ++i)
    {
        for (size_t k = 0; k < 4; ++k)
            private_key[k] = rng();

        for (auto v : private_key)
            blackhole ^= v;
    }

    std::cout << std::hex << blackhole << std::endl;
}
