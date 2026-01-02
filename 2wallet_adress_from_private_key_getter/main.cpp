/*
g++ -Ofast -mavx2 main.cpp -lsecp256k1 && ./a.out
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
#include <map>
#include <random>
#include <cstdint>

const int ADDRESS_LENGTH = 40;

std::atomic<bool> stop_flag(false);
std::atomic<int> total_count(0);
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

// Heuristic for repeating characters from beginning and end (symmetry)
int heuristic_symmetry(const std::string &addr)
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
int heuristic_leading_and_trailing_repeats(const std::string &addr)
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
int heuristic_alternating(const std::string &addr)
{
    int score = 0;

    // From beginning
    if (ADDRESS_LENGTH >= 2) {
        char a = addr[0];
        char b = addr[1];
        if (a != b) {
            int len = 2;
            for (size_t i = 2; i < ADDRESS_LENGTH; ++i) {
                char expected = (i % 2 == 0) ? a : b;
                if (addr[i] != expected) break;
                len++;
            }
            int pairs = len - 1;
            score += pairs;
        }
    }

    // From end
    if (ADDRESS_LENGTH >= 2) {
        char c = addr[ADDRESS_LENGTH - 2];
        char d = addr[ADDRESS_LENGTH - 1];
        if (c != d) {
            int len = 2;
            for (int i = ADDRESS_LENGTH - 3; i >= 0; --i) {
                int pos_from_end = ADDRESS_LENGTH - 1 - i;
                char expected = (pos_from_end % 2 == 0) ? c : d;
                if (addr[i] != expected) break;
                len++;
            }
            int pairs = len - 1;
            score += pairs;
        }
    }

    return (score > 0) ? (1 << score) : 0;
}

// Heuristic for repeated pairs (AABBCC...)
// int heuristic_repeated_pairs(const std::string &addr)
// {

// }

// Heuristic for containing vanity words - more score at start/end
int heuristic_vanity_words(const std::string &addr)
{
    std::string hex_part = addr;
    std::transform(hex_part.begin(), hex_part.end(), hex_part.begin(), ::tolower);
    static std::vector<std::string> vanities = {"beef", "dead", "1337", };

    int score = 0;
    for (const auto &van : vanities)
    {
        size_t pos = hex_part.find(van);
        if (pos != std::string::npos)
        {
            int points = van.size() * 1; // 1 point per character
            if (pos == 0)
                points = van.size() * 3; // at start
            else if (pos + van.size() == ADDRESS_LENGTH)
                points = van.size() * 3; // at end
            score += points;
        }
    }
    return score;
}

inline int get_hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    return 10 + (c - 'A');
}

int heuristic_sequence(const std::string &addr)
{
    int max_score = 0;
    int val = get_hex_value(addr[0]);
    // check ascending
    int len_asc = 1;
    for (size_t j = 1; j < 40; ++j)
    {
        int next_val = get_hex_value(addr[j]);
        if (next_val != val + 1)
            break;
        len_asc++;
        val = next_val;
    }

    // check descending
    val = get_hex_value(addr[0]);
    int len_desc = 1;
    for (size_t j = 1; j < 40; ++j)
    {
        int next_val = get_hex_value(addr[j]);
        if (next_val != val - 1)
            break;
        len_desc++;
        val = next_val;
    }
    max_score = len_asc + len_desc - 2;

    // from end
    val = get_hex_value(addr[39]);
    // check descending from end
    int len_desc_end = 1;
    for (int j = 38; j >= 0; --j)
    {
        int next_val = get_hex_value(addr[j]);
        if (next_val != val - 1)
            break;
        len_desc_end++;
        val = next_val;
    }

    // check ascending from end
    val = get_hex_value(addr[39]);
    int len_asc_end = 1;
    for (int j = 38; j >= 0; --j)
    {
        int next_val = get_hex_value(addr[j]);
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
int heuristic_mostly_same(const std::string &addr)
{
    static int map[256];
    static bool initialized = false;
    if (!initialized) {
        for (int i = 0; i < 256; ++i) map[i] = -1;
        for (char c = '0'; c <= '9'; ++c) map[static_cast<unsigned char>(c)] = c - '0';
        for (char c = 'A'; c <= 'F'; ++c) map[static_cast<unsigned char>(c)] = 10 + (c - 'A');
        for (char c = 'a'; c <= 'f'; ++c) map[static_cast<unsigned char>(c)] = 16 + (c - 'a');
        initialized = true;
    }

    uint8_t counts[22] = {0};

    for (char c : addr) {
        int index = map[static_cast<unsigned char>(c)];
        ++counts[index];
    }

    int hhi = 0;
    __m256i sum = _mm256_setzero_si256();
    size_t i = 0;
    for (; i + 16 < 22; i += 16) {
        __m128i v = _mm_loadu_si128(reinterpret_cast<__m128i*>(&counts[i]));
        __m256i v16 = _mm256_cvtepu8_epi16(v);
        __m256i sq = _mm256_mullo_epi16(v16, v16);
        sum = _mm256_add_epi16(sum, sq);
    }
    for (; i < 22; ++i) {
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

// Main heuristic function
int main_heuristic(const std::string &addr)
{
    int score = 0;
    score += heuristic_symmetry(addr);
    score += heuristic_leading_and_trailing_repeats(addr);
    score += heuristic_sequence(addr);

    // score += heuristic_alternating(addr);
    // score += heuristic_repeated_pairs(addr);
    // score += heuristic_vanity_words(addr);
    score += heuristic_mostly_same(addr);
    return score;
}

void worker_function()
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx)
        return;

    std::random_device rd;
    std::seed_seq seq{rd(), rd(), rd(), rd()};
    std::mt19937_64 rng;
    rng.seed(seq);

    while (!stop_flag)
    {
        uint8_t private_key[32];

        for (int k = 0; k < 4; ++k)
        {
            reinterpret_cast<uint64_t *>(private_key)[k] = rng();
        }

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key))
            continue;

        uint8_t pubkey_ser[65];
        size_t pubkey_len = sizeof(pubkey_ser);
        secp256k1_ec_pubkey_serialize(ctx, pubkey_ser, &pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

        uint8_t hash[32];
        keccak256(pubkey_ser + 1, 64, hash);

        uint8_t wallet_address[20];
        memcpy(wallet_address, hash + 12, 20);

        std::string addr_str = to_checksum_address(wallet_address);

        int score = main_heuristic(addr_str);
        if (score > 50)
        {
            std::lock_guard<std::mutex> lock(file_mutex);
            std::ofstream file("PrettyAddresses.csv", std::ios::app);
            file << score << "," << addr_str << "," << to_hex(private_key, 32) << std::endl;
        }

        total_count++;
    }

    secp256k1_context_destroy(ctx);
}

/* ===================== MAIN ===================== */

struct WalletResult
{
    int score;
    std::string address;
    std::string private_key;
};

int main()
{
    signal(SIGINT, signal_handler);

    // Create worker threads
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0)
        num_threads = 4;
    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back(worker_function);
    }

    // Display thread
    std::thread display_thread([]()
                               {
    auto start_time = std::chrono::high_resolution_clock::now();
    while (!stop_flag)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto current_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = current_time - start_time;
        double speed = total_count.load() / elapsed.count();
        std::cout << "\rGenerated " << total_count.load() << " addresses, speed: " << speed << " addr/sec" << std::flush;
    } });

    // Wait for threads
    for (auto &t : threads)
    {
        t.join();
    }

    stop_flag = true;
    display_thread.join();

    std::cout << std::endl;

    // Read, reevaluate, sort, and write back the results
    std::vector<WalletResult> results;
    std::ifstream infile("PrettyAddresses.csv");
    std::string line;
    // Skip header line
    std::getline(infile, line);
    while (std::getline(infile, line))
    {
        std::stringstream ss(line);
        std::string score_str, addr, priv;
        std::getline(ss, score_str, ',');
        std::getline(ss, addr, ',');
        std::getline(ss, priv, ',');
        // Recalculate score with current heuristic
        int new_score = main_heuristic(addr);
        results.push_back({new_score, addr, priv});
    }
    infile.close();

    std::sort(results.begin(), results.end(), [](const WalletResult &a, const WalletResult &b)
              { return a.score > b.score; });

    std::ofstream outfile("PrettyAddresses.csv");
    outfile << "score,address,private_key" << std::endl;
    for (const auto &res : results)
    {
        outfile << res.score << "," << res.address << "," << res.private_key << std::endl;
    }
    outfile.close();

    return 0;
}
