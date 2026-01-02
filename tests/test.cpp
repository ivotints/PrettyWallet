#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <immintrin.h>
#include <map>
#include <random>
#include <string>
#include <vector>

// Original version (unchanged behavior)
int heuristic_mostly_same_slow(const std::string &addr)
{
    std::map<char, int> count;
    for (char c : addr)
        count[c]++;

    int hhi = 0;
    for (auto &p : count)
        hhi += p.second * p.second;

    return std::max(0, hhi - 200);
}

// Faster version
uint16_t heuristic_mostly_same_fast(const std::string &addr)
{
    uint8_t counts[55] = {0};

    for (unsigned char c : addr)
        ++counts[c - '0'];

    uint16_t hhi = 0;
    for (uint16_t v : counts)
        hhi += v * v; // 40 * 40 = 1600 is max

    if (hhi < 200)
        return 0;

    return hhi;
}

// Optimized for hex chars (0-9, A-F, a-f), length 40
uint16_t heuristic_mostly_same_fast_2(const std::string &addr)
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

    for (char c : addr)
    {
        int index = map[static_cast<unsigned char>(c)];
        ++counts[index];
    }

    uint16_t hhi = 0;
    for (uint8_t v : counts)
        hhi += static_cast<uint16_t>(v) * v;

    if (hhi < 200)
        return 0;

    return hhi;
}

// SIMD-optimized version
uint16_t heuristic_mostly_same_fast_3(const std::string &addr)
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

    for (char c : addr)
    {
        int index = map[static_cast<unsigned char>(c)];
        ++counts[index];
    }

    uint16_t hhi = 0;
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
        hhi += static_cast<uint16_t>(counts[i]) * counts[i];
    }
    __m128i low = _mm256_extracti128_si256(sum, 0);
    __m128i high = _mm256_extracti128_si256(sum, 1);
    __m128i total = _mm_add_epi16(low, high);
    total = _mm_hadd_epi16(total, _mm_setzero_si128());
    total = _mm_hadd_epi16(total, total);
    total = _mm_hadd_epi16(total, total);
    hhi += _mm_extract_epi16(total, 0);

    if (hhi < 200)
        return 0;

    return hhi;
}

// Generate random test strings
std::vector<std::string> make_test_data(
    std::size_t n, std::size_t len)
{
    std::mt19937 rng(12345);
    std::string hex_chars = "0123456789abcdefABCDEF";
    std::uniform_int_distribution<int> ch(0, 21);

    std::vector<std::string> data;
    data.reserve(n);

    for (std::size_t i = 0; i < n; ++i)
    {
        std::string s;
        s.reserve(len);
        for (std::size_t j = 0; j < len; ++j)
            s.push_back(hex_chars[ch(rng)]);
        data.push_back(std::move(s));
    }
    return data;
}

// Benchmark helper
template <typename F>
long long benchmark(F func, const std::vector<std::string> &data)
{
    auto start = std::chrono::high_resolution_clock::now();
    volatile int sink = 0; // prevent optimization
    for (const auto &s : data)
        sink += func(s);
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(end - start)
        .count();
}

int main()
{
    constexpr std::size_t N = 2000000;
    constexpr std::size_t LEN = 40;

    auto data = make_test_data(N, LEN);

    // Correctness check
    for (std::size_t i = 0; i < N / 100; ++i)
    {
        if (heuristic_mostly_same_slow(data[i]) !=
            (int)heuristic_mostly_same_fast(data[i]))
        {
            std::cerr << "Mismatch at index " << i << "\n";
            return 1;
        }
        if (heuristic_mostly_same_slow(data[i]) !=
            heuristic_mostly_same_fast_2(data[i]))
        {
            std::cerr << "Mismatch fast_2 at index " << i << "\n";
            return 1;
        }
        if (heuristic_mostly_same_slow(data[i]) !=
            heuristic_mostly_same_fast_3(data[i]))
        {
            std::cerr << "Mismatch fast_3 at index " << i << "\n";
            return 1;
        }
    }

    auto t1 = benchmark(heuristic_mostly_same_slow, data);
    auto t2 = benchmark(heuristic_mostly_same_fast, data);
    auto t3 = benchmark(heuristic_mostly_same_fast_2, data);
    auto t4 = benchmark(heuristic_mostly_same_fast_3, data);

    std::cout << "Slow version: " << t1 << " us\n";
    std::cout << "Fast version: " << t2 << " us\n";
    std::cout << "Fast_2 version: " << t3 << " us\n";
    std::cout << "Fast_3 version: " << t4 << " us\n";
    std::cout << "Speedup fast vs slow: "
              << static_cast<double>(t1) / t2 << "x\n";
    std::cout << "Speedup fast_2 vs slow: "
              << static_cast<double>(t1) / t3 << "x\n";
    std::cout << "Speedup fast_3 vs slow: "
              << static_cast<double>(t1) / t4 << "x\n";
}
