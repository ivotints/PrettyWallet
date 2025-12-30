/*
g++ main.cpp -lsecp256k1 && ./a.out
*/

#include <secp256k1.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <stdint.h>
#include "../1private_key_generator/PrivateKeyGenerator.hpp"
#include <array>
#include <string>
#include <sstream>

/* ===================== KECCAK-256 ===================== */

static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL};

static const int keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

static const int keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

static void keccakf(uint64_t st[25])
{
    for (int round = 0; round < 24; round++)
    {
        uint64_t bc[5], t;

        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (int i = 0; i < 5; i++)
        {
            t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63));
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        t = st[1];
        for (int i = 0; i < 24; i++)
        {
            int j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
            t = bc[0];
        }

        for (int j = 0; j < 25; j += 5)
        {
            for (int i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        st[0] ^= keccakf_rndc[round];
    }
}

void keccak256(const uint8_t *in, size_t inlen, uint8_t out[32])
{
    uint64_t st[25];
    uint8_t temp[144];
    memset(st, 0, sizeof(st));

    size_t rate = 136;
    size_t offset = 0;

    while (inlen >= rate)
    {
        for (size_t i = 0; i < rate; i++)
            ((uint8_t *)st)[i] ^= in[offset + i];
        keccakf(st);
        offset += rate;
        inlen -= rate;
    }

    memset(temp, 0, rate);
    memcpy(temp, in + offset, inlen);
    temp[inlen] = 0x01;
    temp[rate - 1] |= 0x80;

    for (size_t i = 0; i < rate; i++)
        ((uint8_t *)st)[i] ^= temp[i];

    keccakf(st);
    memcpy(out, st, 32);
}

static std::string to_hex(const uint8_t *data, size_t len, bool uppercase = false)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    if (uppercase)
        oss << std::uppercase;
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << (unsigned)data[i];
    return oss.str();
}

static std::string to_checksum_address(const uint8_t addr20[20])
{
    std::string addr_hex = to_hex(addr20, 20, false);
    uint8_t hash[32];
    keccak256((const uint8_t *)addr_hex.c_str(), addr_hex.size(), hash);

    std::string out = "0x";
    for (size_t i = 0; i < addr_hex.size(); ++i)
    {
        char c = addr_hex[i];
        if (c >= 'a' && c <= 'f')
        {
            uint8_t nibble;
            if ((i & 1) == 0)
                nibble = (hash[i / 2] >> 4) & 0xF;
            else
                nibble = hash[i / 2] & 0xF;
            if (nibble >= 8)
                c = char(c - 'a' + 'A');
        }
        out.push_back(c);
    }
    return out;
}

/* ===================== MAIN ===================== */

int main()
{
    ///////////////////initialization
    PrivateKeyGenerator gen;
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx)
        return 1;
    ////////////////////////////////

    for (int count = 0; count < 5; ++count) {
        uint8_t private_key[32];

        ////// Private key generation
        //do {
        gen.generate_into(reinterpret_cast<uint64_t*>(private_key));
        //} while (!secp256k1_ec_seckey_verify(ctx, private_key));  // very unlikely, can be removed for optimization
        /////////////////////////////

        ////// DEBUG PRINTING
        std::cout << "Private key:    ";
        for (size_t i = 0; i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(private_key[i]);
        }
        std::cout << std::endl;
        /////////////////////

        /////// Public key creation
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
            std::cerr << "Failed to create pubkey\n";
            continue;
        }
        ////////////////////////////

        ////// Public key serialization
        uint8_t pubkey_ser[65];
        size_t pubkey_len = sizeof(pubkey_ser);
        secp256k1_ec_pubkey_serialize(ctx, pubkey_ser, &pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        ///////////////////////////////

        ////// DEBUG PRINTING
        std::cout << "Public key:     ";
        for (size_t i = 0; i < 65; ++i) {  // skip 0x04 prefix, print 64 bytes
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(pubkey_ser[i]);
        }
        std::cout << std::endl;
        /////////////////////

        ///// Hash creation from public key
        uint8_t hash[32];
        keccak256(pubkey_ser + 1, 64, hash); // skip 0x04
        ////////////////////////////////////

        ///// Wallet address copy from hash
        uint8_t wallet_address[20];
        memcpy(wallet_address, hash + 12, 20);
        /////////////////////////////////

        ////// DEBUG PRINTING
        std::cout << "Wallet address: " << to_checksum_address(wallet_address) << std::endl
                  << std::endl;
        /////////////////////

        // here i will take wallet adress and send to heuristic function, which will evaluate how beautifull is adress
        // and it will assign score to adress
        // and if score is more than ... lets say 10 points, it will save adress to file called "PrettyAdreses.csv"
        // in format:
        // <score>,<wallet_address>,<private_key>
        // 101,0x000035C1284Ad65f416f9a10B05f6d1f8c8A0000,044587cc492051b8e1e0275c68f6d10154a41c207282ea7dccf8755f2138e2abb13dba8bd9d602442936cb5bc73a9c6c55fac3cfad5affe574d7bae2f758aa6b3b
    }

    secp256k1_context_destroy(ctx);
}
