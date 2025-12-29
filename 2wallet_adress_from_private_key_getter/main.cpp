// g++ main.cpp -lsecp256k1 && ./a.out

#include <secp256k1.h>
#include <iostream>
#include <iomanip>
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

/* ===================== MAIN ===================== */

int main() {
    const char* priv_hex =
        "365ec9632b462ca39bc621571f8950e5da329fda37e5581e489094401a7f0db2";

    uint8_t privkey[32];
    for (int i = 0; i < 32; i++)
        sscanf(priv_hex + 2*i, "%2hhx", &privkey[i]);

    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, privkey);

    uint8_t pubkey_ser[65];
    size_t pubkey_len = 65;

    secp256k1_ec_pubkey_serialize(
        ctx, pubkey_ser, &pubkey_len,
        &pubkey, SECP256K1_EC_UNCOMPRESSED
    );

    uint8_t hash[32];
    keccak256(pubkey_ser + 1, 64, hash);

    std::cout << "0x";
    for (int i = 12; i < 32; i++)
        std::cout << std::hex << std::setw(2)
                  << std::setfill('0') << (int)hash[i];
    std::cout << std::endl;

    secp256k1_context_destroy(ctx);
}
