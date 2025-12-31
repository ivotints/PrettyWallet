#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

// Heuristic for repeating characters from beginning and end (symmetry)
int heuristic_symmetry(const std::string &addr)
{
    int score = 0;
    for (int i = 0; i < 20; ++i)
    {
        if (addr[i] == addr[39 - i])
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
    for (int i = 1; i < 40; i++)
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

    char trailing_c = addr[39];
    int trailing_count = 1;
    // count amount of that character from end
    for (int i = 38; i >= 0; i--)
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

int heuristic_mostly_same(const std::string &addr)
{
    std::map<char, int> count;
    for (char c : addr)
        count[c]++;
    int hhi = 0;
    for (auto &p : count) {
        hhi += p.second * p.second;
    }
    return std::max(0, hhi - 200);
}


int main()
{
    std::vector<std::string> test_addresses = {
        "eE214fA8960dc685D6Bbb5eB1Eb8dB668F5e7a61",
        "1111411116111685D11111e1111811118F511111",
        "11223344556677889900aabbccddeeffAABBCDEF",
        "c14C5C4DFD05555c312AD8cF000A555555555555",
    };

    for (const auto &addr : test_addresses)
    {
        int score = 0;
        score += heuristic_mostly_same(addr);

        std::cout << "Address: " << addr << " - " << score << std::endl;
    }

    return 0;
}
