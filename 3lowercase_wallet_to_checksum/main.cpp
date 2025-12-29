// g++ main.cpp && ./a.out

#include <iostream>
#include <string>
#include <cctype>
#include <cstring>
#include <stdint.h>

/* ===================== KECCAK-256 ===================== */

static const uint64_t keccakf_rndc[24] = {
  0x0000000000000001ULL,0x0000000000008082ULL,
  0x800000000000808aULL,0x8000000080008000ULL,
  0x000000000000808bULL,0x0000000080000001ULL,
  0x8000000080008081ULL,0x8000000000008009ULL,
  0x000000000000008aULL,0x0000000000000088ULL,
  0x0000000080008009ULL,0x000000008000000aULL,
  0x000000008000808bULL,0x800000000000008bULL,
  0x8000000000008089ULL,0x8000000000008003ULL,
  0x8000000000008002ULL,0x8000000000000080ULL,
  0x000000000000800aULL,0x800000008000000aULL,
  0x8000000080008081ULL,0x8000000000008080ULL,
  0x0000000080000001ULL,0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
  1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44
};

static const int keccakf_piln[24] = {
  10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1
};

static void keccakf(uint64_t st[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t bc[5], t;

        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];

        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ ((bc[(i+1)%5] << 1) | (bc[(i+1)%5] >> 63));
            for (int j = 0; j < 25; j += 5)
                st[j+i] ^= t;
        }

        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
            t = bc[0];
        }

        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = st[j+i];
            for (int i = 0; i < 5; i++)
                st[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
        }

        st[0] ^= keccakf_rndc[round];
    }
}

void keccak256(const uint8_t* in, size_t inlen, uint8_t out[32]) {
    uint64_t st[25];
    uint8_t temp[144];
    memset(st, 0, sizeof(st));

    size_t rate = 136;
    size_t offset = 0;

    while (inlen >= rate) {
        for (size_t i = 0; i < rate; i++)
            ((uint8_t*)st)[i] ^= in[offset + i];
        keccakf(st);
        offset += rate;
        inlen -= rate;
    }

    memset(temp, 0, rate);
    memcpy(temp, in + offset, inlen);
    temp[inlen] = 0x01;
    temp[rate - 1] |= 0x80;

    for (size_t i = 0; i < rate; i++)
        ((uint8_t*)st)[i] ^= temp[i];

    keccakf(st);
    memcpy(out, st, 32);
}

/* ===================== EIP-55 CHECKSUM ===================== */

std::string checksum_address(const std::string& addr_lower) {
    uint8_t hash[32];
    keccak256(reinterpret_cast<const uint8_t*>(addr_lower.data()),
              addr_lower.size(), hash);

    std::string out;
    for (int i = 0; i < 40; i++) {
        char c = addr_lower[i];
        if (c >= 'a' && c <= 'f') {
            int nibble = (hash[i / 2] >> ((1 - (i % 2)) * 4)) & 0xF;
            if (nibble >= 8)
                c = std::toupper(c);
        }
        out.push_back(c);
    }
    return "0x" + out;
}

/* ===================== MAIN ===================== */

int main() {
    std::string addr =
        "feaae42ad4a0e68d55aabb2e0cb85368d4900b39";

    std::cout << checksum_address(addr) << std::endl;
    return 0;
}

