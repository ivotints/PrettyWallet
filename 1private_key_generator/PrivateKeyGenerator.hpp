#pragma once

#include <random>
#include <cstdint>

class PrivateKeyGenerator {
    public:
        PrivateKeyGenerator() {
            std::random_device rd;
            std::seed_seq seq{rd(), rd(), rd(), rd()};
            // rng.seed(seq);
            rng.seed(1); // use for debug
        }

        inline void generate_into(uint64_t out[4]) noexcept {
            for (size_t k = 0; k < 4; ++k)
                out[k] = rng();
        }

    private:
        std::mt19937_64 rng;
};
