#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#define ADDRESS_LENGTH 40

// Heuristic for alternating characters: reward for runs of same characters on even and odd positions
int heuristic_alternating(const std::string &addr)
{

}

int main()
{
    std::vector<std::string> test_addresses = {
        "01....................................00",
        "0101..................................00",
        "010101................................00",
        "01010101..............................00",
        "0101010101............................00",
        "010101010101..........................00",
        "01....................................10",
        "01..................................1010",
        "01................................101010",
        "01..............................10101010",
        "ab..............................10101010",
    };

    for (const auto &addr : test_addresses)
    {
        int score = 0;
        score += heuristic_alternating(addr);

        std::cout << "Address: " << addr << " - " << score << std::endl;
    }

    return 0;
}
