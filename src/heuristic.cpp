#include "PrettyWalletGenerator.hpp"
#include "hex_tables.hpp"

// Pre-computed lookup tables for hex conversion (initialized once)
alignas(64) char hex_chars_lower[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
alignas(64) int hex_values[256];
alignas(64) bool hex_valid[256];

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

// Heuristic for concentration of characters (like monopoly index) - SIMD version for Linux
#ifndef _WIN32
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
#endif

// Heuristic for concentration of characters (like monopoly index) - no SIMD version for Windows
#ifdef _WIN32
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
        if (index >= 0 && index < 22)
        {
            ++counts[index];
        }
    }

    int hhi = 0;
    for (int i = 0; i < 22; ++i)
    {
        hhi += static_cast<int>(counts[i]) * counts[i];
    }

    hhi -= 200;
    if (hhi < 0)
        hhi = 0;

    return hhi;
}
#endif

int main_heuristic(const char *addr)
{
    int score = 0;
    score += heuristic_symmetry(addr);
    score += heuristic_leading_and_trailing_repeats(addr);
    score += heuristic_sequence(addr);
    score += heuristic_vanity_words(addr);
    score += heuristic_mostly_same(addr);
    return score;
}
