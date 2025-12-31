#include <iostream>
#include <string>
#include <vector>

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
    if (score > 0) {
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
    for (int i = 1; i < 40; i++) {
        if (addr[i] == leading_c) {
            leading_count++;
        }
        else {
            break;
        }
    }

    char trailing_c = addr[39];
    int trailing_count = 1;
    // count amount of that character from end
    for (int i = 38; i >= 0; i--) {
        if (addr[i] == trailing_c) {
            trailing_count++;
        }
        else {
            break;
        }
    }

    if (leading_c == trailing_c) {
        return (1 << (trailing_count + leading_count) - 1);
    }
    int score = 0;
    if (trailing_count > 1) {
        score += 1 << trailing_count - 1;
    }
    if (leading_count > 1) {
        score += 1 << leading_count - 1;
    }
    return score;










    // // Leading
    // char leading_c = addr[2];
    // int leading_count = 1;
    // for (size_t i = 3; i < addr.size(); ++i)
    // {
    //     if (addr[i] == leading_c)
    //         leading_count++;
    //     else
    //         break;
    // }

    // // Trailing
    // char trailing_c = addr.back();
    // int trailing_count = 1;
    // for (int i = addr.size() - 2; i >= 2; --i)
    // {
    //     if (addr[i] == trailing_c)
    //         trailing_count++;
    //     else
    //         break;
    // }

    // int score = 0;
    // if (leading_c == trailing_c)
    // {
    //     // Same character, combine the counts for higher score
    //     score = 1 << (leading_count + trailing_count - 2);
    // }
    // else
    // {
    //     // Different characters, score separately
    //     if (leading_count > 1)
    //         score += 1 << (leading_count - 2);
    //     if (trailing_count > 1)
    //         score += 1 << (trailing_count - 2);
    // }
    // return score;
}

int main()
{
    std::vector<std::string> test_addresses = {
        "5-==--==--=--==-=-==-=--==-g...........a",
        "55-==--==--=--==-=-==-=--==-g..........a",
        "555-==--==--=--==-=-==-=--==-g.........a",
        "5555-==--==--=--==-=-==-=--==-g........a",
        "55555-==--==--=--==-=-==-=--==-g.......a",
        "5-==--==--=--==-=-==-=--==-g..........aa",
        "5-==--==--=--==-=-==-=--==-g.........aaa",
        "5-==--==--=--==-=-==-=--==-g........aaaa",
        "5-==--==--=--==-=-==-=--==-g.......aaaaa",
        "5-==--==--=--==-=-==-=--==-g......aaaaaa",
        "5-==--==--=--==-=-==-=--==-g...........a",
        "55-==--==--=--==-=-==-=--==-g.........aa",
        "555-==--==--=--==-=-==-=--==-g.......aaa",
        "5555-==--==--=--==-=-==-=--==-g.....aaaa",
        "55555-==--==--=--==-=-==-=--==-g...aaaaa",
        "555555-==--==--=--==-=-==-=--==-g.aaaaaa",
        "5-==--==--=--==-=-==-=--==-g...........5",
        "55-==--==--=--==-=-==-=--==-g.........55",
        "555-==--==--=--==-=-==-=--==-g.......555",
        "5555-==--==--=--==-=-==-=--==-g.....5555",
        "55555-==--==--=--==-=-==-=--==-g...55555",

    };

    for (const auto &addr : test_addresses)
    {
        int score = 0;
        score += heuristic_symmetry(addr);
        score += heuristic_leading_and_trailing_repeats(addr);
        std::cout << "Address: " << addr << " - " << score << std::endl;
    }

    return 0;
}
