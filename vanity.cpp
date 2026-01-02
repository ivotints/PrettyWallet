#include "vanity.hpp"
#include <array>
#include <utility>
#include <cstring>

constexpr int ALPHABET = 22;
constexpr int MAX_NODES = 512;

struct ConstNode
{
    std::array<int, ALPHABET> next;
    bool terminal;
    constexpr ConstNode() : next{}, terminal(false)
    {
        for (int i = 0; i < ALPHABET; ++i)
            next[i] = -1;
    }
};

// Map char to number using requested layout (assumes valid input):
// '0'-'9' -> 0..9
// 'a'-'f' -> 10..15
// 'A'-'F' -> 16..21
static constexpr int map_char_const(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0'; // 0..9
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a'); // 10..15
    // A-F
    return 16 + (c - 'A'); // 16..21
}

// Add a word into nodes array at compile time. Returns new nodes_count.
static constexpr int add_word_const(std::array<ConstNode, MAX_NODES> &nodes, int nodes_count, const char *s)
{
    int v = 0;
    for (const char *p = s; *p; ++p)
    {
        int c = map_char_const(*p);
        int next = nodes[v].next[c];
        if (next == -1)
        {
            next = nodes_count;
            nodes[v].next[c] = next;
            // nodes[next] default constructed with next filled with -1
            ++nodes_count;
            if (nodes_count >= MAX_NODES)
                return nodes_count; // avoid overflow
        }
        v = next;
    }
    nodes[v].terminal = true;
    return nodes_count;
}

// Build trie at compile time
static constexpr std::pair<std::array<ConstNode, MAX_NODES>, int> build_trie()
{
    std::array<ConstNode, MAX_NODES> nodes{};
    int nodes_count = 1;

    const char *words[] = {
        "c0ffee", "C0ffee", "C0FFEE",
        "cafe", "Cafe", "CAFE",
        "ace", "Ace", "ACE",
        "beef", "Beef", "BEEF",
        "dead", "Dead", "DEAD",
        "deface", "Deface", "DEFACE",
        "decade", "Decade", "DECADE",
        "facade", "Facade", "FACADE",
        "1337",
        "babe", "Babe", "BABE",
        "face", "Face", "FACE",
        "fade", "Fade", "FADE",
        "feed", "Feed", "FEED",
        "c0de", "C0de", "C0DE",
        "b00b", "B00b", "B00B",
        "f00d", "F00d", "F00D",
        "bead", "Bead", "BEAD",
        "deaf", "Deaf", "DEAF",
        "deed", "Deed", "DEED",
        "add", "Add", "ADD",
        "bad", "Bad", "BAD",
        "bed", "Bed", "BED",
        "bee", "Bee", "BEE",
        "cab", "Cab", "CAB",
        "dad", "Dad", "DAD",
        "fab", "Fab", "FAB",
        "fee", "Fee", "FEE",
        "d0c", "D0c", "D0C"};

    for (const char *w : words)
        nodes_count = add_word_const(nodes, nodes_count, w);

    return {nodes, nodes_count};
}

inline constexpr auto TRIE_BUILT = build_trie();
inline constexpr std::array<ConstNode, MAX_NODES> CONST_TRIE = TRIE_BUILT.first;
inline constexpr int CONST_NODES = TRIE_BUILT.second;

// match the longest word from s[pos..limit-1] using compile-time trie
static inline int match_from(const char *s, int pos, int limit)
{
    int best = 0;
    int v = 0;

    for (int i = pos; i < limit; ++i)
    {
        int c = map_char_const(s[i]);
        int next = CONST_TRIE[v].next[c];
        if (next == -1)
            break;
        v = next;
        if (CONST_TRIE[v].terminal)
            best = i - pos + 1;
    }
    return best;
}

int heuristic_vanity_words_lowercase(const char *addr) {
    int score = 0;

    score -= 2; // i dont like lowercase
    return score ? score > 0 : 0;
}

int heuristic_vanity_words_uppercase(const char *addr) {
    int score = 0;

    score -= 1; // i dont like uppercase
    return score ? score > 0 : 0;
}

int heuristic_vanity_words_capital(const char *addr) {
    int score = 0;

    return score;
}


// Consolidated vanity heuristic (trie-based matching with greedy partitioning)
int heuristic_vanity_words(const char *addr)
{
    // here will be just call of 3 functions and return;
    // int score = 0;

    // score += heuristic_vanity_words_lowercase(addr);
    // score += heuristic_vanity_words_uppercase(addr);
    // score += heuristic_vanity_words_capital(addr);


    //return score ? (1 << score) : 0;

    int score = 0;
    int start = 0;
    int end = ADDRESS_LENGTH;

    // Greedy from the beginning: take the longest match at each step
    while (start < end)
    {
        int len = match_from(addr, start, end);
        if (!len)
            break;
        score += len;
        start += len;
    }

    // Greedy from the end: take the longest suffix matches
    while (start < end)
    {
        int best = 0;
        for (int i = end - 1; i >= start; --i)
        {
            int len = match_from(addr, i, end);
            if (i + len == end && len > best)
                best = len;
        }
        if (!best)
            break;
        score += best;
        end -= best;
    }

    return score ? (1 << score) : 0;
}
