#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>

static volatile uint64_t blackhole = 0;

static inline uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

int main(void)
{
    uint64_t state;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    state = ((uint64_t)ts.tv_nsec << 32) ^ (uint64_t)ts.tv_sec ^ (uint64_t)getpid();

    uint64_t private_key[4];

    for (uint64_t i = 0; i < 1000000000ULL; ++i) {
        for (int k = 0; k < 4; ++k)
            private_key[k] = splitmix64(&state);

        for (int k = 0; k < 4; ++k)
            blackhole ^= private_key[k];
    }

    printf("%" PRIx64 "\n", blackhole);
    return 0;
}
