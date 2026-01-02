/*
g++ -Ofast -march=native -flto -funroll-loops main.cpp -lsecp256k1 -pthread && ./a.out
*/

#include <secp256k1.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <stdint.h>
#include <immintrin.h>
#include <array>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <csignal>
#include <chrono>
#include <cctype>
#include <thread>
#include <mutex>
#include <atomic>
#include <random>
#include <cstdint>
#include <unordered_set>

#include "vanity.hpp"

// Pre-computed lookup tables for hex conversion (initialized once)
alignas(64) static char hex_chars_lower[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
alignas(64) static int hex_values[256];
alignas(64) static bool hex_valid[256];

// Initialize lookup tables
static struct HexTableInit
{
    HexTableInit()
    {
        std::memset(hex_values, 0, sizeof(hex_values));
        std::memset(hex_valid, 0, sizeof(hex_valid));
        for (int i = 0; i < 10; ++i)
        {
            hex_values['0' + i] = i;
            hex_valid['0' + i] = true;
        }
        for (int i = 0; i < 6; ++i)
        {
            hex_values['a' + i] = 10 + i;
            hex_values['A' + i] = 10 + i;
            hex_valid['a' + i] = true;
            hex_valid['A' + i] = true;
        }
    }
} hex_table_init;

std::atomic<bool> stop_flag(false);
std::atomic<uint64_t> total_count(0);
std::mutex file_mutex;

void signal_handler(int signal)
{
    stop_flag = true;
}

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
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
        char c1 = hex_chars_lower[data[i] >> 4];
        char c2 = hex_chars_lower[data[i] & 0xF];
        if (uppercase)
        {
            if (c1 >= 'a')
                c1 -= 32;
            if (c2 >= 'a')
                c2 -= 32;
        }
        result.push_back(c1);
        result.push_back(c2);
    }
    return result;
}

// Fast hex conversion directly to char array (no allocation)
static void to_hex_fast(const uint8_t *data, size_t len, char *out)
{
    for (size_t i = 0; i < len; ++i)
    {
        out[i * 2] = hex_chars_lower[data[i] >> 4];
        out[i * 2 + 1] = hex_chars_lower[data[i] & 0xF];
    }
}

static std::string to_checksum_address(const uint8_t addr20[20])
{
    std::string addr_hex = to_hex(addr20, 20, false);
    uint8_t hash[32];
    keccak256((const uint8_t *)addr_hex.c_str(), addr_hex.size(), hash);

    std::string out = "";
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

/* ===================== HEURISTICS ===================== */

// Fast inline hex value lookup
inline int get_hex_value(char c)
{
    return hex_values[static_cast<unsigned char>(c)];
}

// Convert address to lowercase in-place (for pattern matching)
inline void to_lower_inplace(char *addr, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        if (addr[i] >= 'A' && addr[i] <= 'F')
        {
            addr[i] += 32;
        }
    }
}

// Heuristic for repeating characters from beginning and end (symmetry)
int heuristic_symmetry(const char *addr)
{
    int score = 0;
    for (int i = 0; i < ADDRESS_LENGTH / 2; ++i)
    {
        if (addr[i] == addr[ADDRESS_LENGTH - 1 - i])
            score += 1;
        else
            break;
    }
    if (score > 0)
    {
        return (1 << score);
    }
    return 0;
}

// Heuristic for leading repeats of same character
int heuristic_leading_and_trailing_repeats(const char *addr)
{
    char leading_c = addr[0];
    int leading_count = 1;
    // count amount of that character from the front
    for (int i = 1; i < ADDRESS_LENGTH; i++)
    {
        if (addr[i] == leading_c)
        {
            leading_count++;
        }
        else
        {
            break;
        }
    }

    char trailing_c = addr[ADDRESS_LENGTH - 1];
    int trailing_count = 1;
    // count amount of that character from end
    for (int i = ADDRESS_LENGTH - 2; i >= 0; i--)
    {
        if (addr[i] == trailing_c)
        {
            trailing_count++;
        }
        else
        {
            break;
        }
    }

    if (leading_c == trailing_c)
    {
        return (1 << (trailing_count + leading_count) - 1);
    }
    int score = 0;
    if (trailing_count > 1)
    {
        score += 1 << trailing_count - 1;
    }
    if (leading_count > 1)
    {
        score += 1 << leading_count - 1;
    }
    return score;
}

// Heuristic for alternating characters (ABABAB...) from beginning and end
int heuristic_alternating(const char *addr)
{
    int score = 0;

    // From beginning
    char a = addr[0];
    char b = addr[1];
    if (a >= 'A' && a <= 'F')
        a += 32;
    if (b >= 'A' && b <= 'F')
        b += 32;

    if (a != b)
    {
        int len = 2;
        for (int i = 2; i < ADDRESS_LENGTH; ++i)
        {
            char c = addr[i];
            if (c >= 'A' && c <= 'F')
                c += 32;
            char expected = (i % 2 == 0) ? a : b;
            if (c != expected)
                break;
            len++;
        }
        if (len >= 4)
        {
            score += (len - 2) * 2;
        }
    }

    // From end
    char c1 = addr[ADDRESS_LENGTH - 2];
    char d = addr[ADDRESS_LENGTH - 1];
    if (c1 >= 'A' && c1 <= 'F')
        c1 += 32;
    if (d >= 'A' && d <= 'F')
        d += 32;

    if (c1 != d)
    {
        int len = 2;
        for (int i = ADDRESS_LENGTH - 3; i >= 0; --i)
        {
            char c = addr[i];
            if (c >= 'A' && c <= 'F')
                c += 32;
            int pos_from_end = ADDRESS_LENGTH - 1 - i;
            char expected = (pos_from_end % 2 == 0) ? c1 : d;
            if (c != expected)
                break;
            len++;
        }
        if (len >= 4)
        {
            score += (len - 2) * 2;
        }
    }

    return (score > 0) ? (1 << score) : 0;
}

// Heuristic for repeated pairs (AABBCCDD...)
int heuristic_repeated_pairs(const char *addr)
{
    int score = 0;

    // From beginning
    int pair_count = 0;
    for (int i = 0; i + 1 < ADDRESS_LENGTH; i += 2)
    {
        char c1 = addr[i];
        char c2 = addr[i + 1];
        if (c1 >= 'A' && c1 <= 'F')
            c1 += 32;
        if (c2 >= 'A' && c2 <= 'F')
            c2 += 32;
        if (c1 == c2)
        {
            pair_count++;
        }
        else
        {
            break;
        }
    }
    if (pair_count >= 2)
    {
        score += pair_count * 2;
    }

    // From end
    int end_pair_count = 0;
    for (int i = ADDRESS_LENGTH - 1; i >= 1; i -= 2)
    {
        char c1 = addr[i - 1];
        char c2 = addr[i];
        if (c1 >= 'A' && c1 <= 'F')
            c1 += 32;
        if (c2 >= 'A' && c2 <= 'F')
            c2 += 32;
        if (c1 == c2)
        {
            end_pair_count++;
        }
        else
        {
            break;
        }
    }
    if (end_pair_count >= 2)
    {
        score += end_pair_count * 2;
    }

    return (score > 0) ? (1 << score) : 0;
}

// Trie-based matching and vanity heuristic moved to tests/vanity.cpp

int heuristic_sequence(const char *addr)
{
    int max_score = 0;
    int val = hex_values[static_cast<unsigned char>(addr[0])];

    // check ascending from start
    int len_asc = 1;
    for (int j = 1; j < 40; ++j)
    {
        int next_val = hex_values[static_cast<unsigned char>(addr[j])];
        if (next_val != val + 1)
            break;
        len_asc++;
        val = next_val;
    }

    // check descending from start
    val = hex_values[static_cast<unsigned char>(addr[0])];
    int len_desc = 1;
    for (int j = 1; j < 40; ++j)
    {
        int next_val = hex_values[static_cast<unsigned char>(addr[j])];
        if (next_val != val - 1)
            break;
        len_desc++;
        val = next_val;
    }
    max_score = len_asc + len_desc - 2;

    // from end - check descending
    val = hex_values[static_cast<unsigned char>(addr[39])];
    int len_desc_end = 1;
    for (int j = 38; j >= 0; --j)
    {
        int next_val = hex_values[static_cast<unsigned char>(addr[j])];
        if (next_val != val - 1)
            break;
        len_desc_end++;
        val = next_val;
    }

    // check ascending from end
    val = hex_values[static_cast<unsigned char>(addr[39])];
    int len_asc_end = 1;
    for (int j = 38; j >= 0; --j)
    {
        int next_val = hex_values[static_cast<unsigned char>(addr[j])];
        if (next_val != val + 1)
            break;
        len_asc_end++;
        val = next_val;
    }
    max_score += len_asc_end + len_desc_end - 2;

    // bonus for starting from begining like 0 for acending, 1 for odd, f for decending.
    int bonus = 1;
    if (len_asc >= 2 && (addr[0] == '1' || addr[0] == '0' || addr[0] == 'a' || addr[0] == 'A'))
        bonus = 2;
    else if (len_desc >= 2 && (addr[0] == '9' || addr[0] == 'f' || addr[0] == 'F'))
        bonus = 2;
    else if (len_desc_end >= 2 && (addr[39] == 'f' || addr[39] == 'F' || addr[39] == '9'))
        bonus = 2;
    else if (len_asc_end >= 2 && (addr[39] == '1' || addr[39] == '0' || addr[39] == 'a' || addr[39] == 'A'))
        bonus = 2;

    if (max_score >= 2)
        return bonus * (1 << (max_score - 1));
    return 0;
}

// Heuristic for concentration of characters (like monopoly index)
int heuristic_mostly_same(const char *addr)
{
    static int map[256];
    static bool initialized = false;
    if (!initialized)
    {
        for (int i = 0; i < 256; ++i)
            map[i] = -1;
        for (char c = '0'; c <= '9'; ++c)
            map[static_cast<unsigned char>(c)] = c - '0';
        for (char c = 'A'; c <= 'F'; ++c)
            map[static_cast<unsigned char>(c)] = 10 + (c - 'A');
        for (char c = 'a'; c <= 'f'; ++c)
            map[static_cast<unsigned char>(c)] = 16 + (c - 'a');
        initialized = true;
    }

    uint8_t counts[22] = {0};

    for (int i = 0; i < ADDRESS_LENGTH; i++)
    {
        int index = map[static_cast<unsigned char>(addr[i])];
        ++counts[index];
    }

    int hhi = 0;
    __m256i sum = _mm256_setzero_si256();
    size_t i = 0;
    for (; i + 16 < 22; i += 16)
    {
        __m128i v = _mm_loadu_si128(reinterpret_cast<__m128i *>(&counts[i]));
        __m256i v16 = _mm256_cvtepu8_epi16(v);
        __m256i sq = _mm256_mullo_epi16(v16, v16);
        sum = _mm256_add_epi16(sum, sq);
    }
    for (; i < 22; ++i)
    {
        hhi += static_cast<int>(counts[i]) * counts[i];
    }
    __m128i low = _mm256_extracti128_si256(sum, 0);
    __m128i high = _mm256_extracti128_si256(sum, 1);
    __m128i total = _mm_add_epi16(low, high);
    total = _mm_hadd_epi16(total, _mm_setzero_si128());
    total = _mm_hadd_epi16(total, total);
    total = _mm_hadd_epi16(total, total);
    hhi += _mm_extract_epi16(total, 0);

    hhi -= 200;
    if (hhi < 0)
        hhi = 0;

    return hhi;
}

int main_heuristic(const char *addr)
{
    int score = 0;
    score += heuristic_symmetry(addr);
    score += heuristic_leading_and_trailing_repeats(addr);
    score += heuristic_sequence(addr);
    // score += heuristic_alternating(addr);
    // score += heuristic_repeated_pairs(addr);
    score += heuristic_vanity_words(addr);
    score += heuristic_mostly_same(addr);
    // score += heuristic_palindrome(addr);
    // score += heuristic_numeric_pattern(addr);
    return score;
}

// Print per-heuristic contributions for a hardcoded address
static void evaluate_hardcoded_address()
{
    const std::string full = "99999FcE889D3a2de60029d989034d5c0D299999";
    std::string addr = full;
    if (addr.size() == 42 && addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X'))
        addr = addr.substr(2);
    if (addr.size() != ADDRESS_LENGTH)
    {
        std::cerr << "Address has wrong length: " << addr.size() << "\n";
        return;
    }

    std::cout << "Evaluating: " << full << "\n";
    int s_sym = heuristic_symmetry(addr.c_str());
    int s_lead = heuristic_leading_and_trailing_repeats(addr.c_str());
    int s_seq = heuristic_sequence(addr.c_str());
    int s_van = heuristic_vanity_words(addr.c_str());
    int s_most = heuristic_mostly_same(addr.c_str());
    int total = s_sym + s_lead + s_seq + s_van + s_most;
    int sanity = main_heuristic(addr.c_str()); // confirmation

    std::vector<std::pair<std::string, int>> parts = {
        {"symmetry", s_sym},
        {"leading_and_trailing_repeats", s_lead},
        {"sequence", s_seq},
        {"vanity_words", s_van},
        {"mostly_same", s_most}};
    std::sort(parts.begin(), parts.end(), [](auto &a, auto &b)
              { return a.second > b.second; });

    std::cout << "Breakdown (largest first):\n";
    for (auto &p : parts)
    {
        std::cout << "  " << p.first << ": " << p.second << "\n";
    }
    std::cout << "Sum of parts: " << total << "  main_heuristic(addr): " << sanity << "\n";
}

int main()
{
    evaluate_hardcoded_address();
}
