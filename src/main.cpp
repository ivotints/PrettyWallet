/*
g++ -Ofast -march=native -flto -funroll-loops main.cpp -lsecp256k1 -pthread && ./a.out
*/
#include "PrettyWalletGenerator.hpp"
#include "hex_tables.hpp"
#include "keccak.hpp"
#include "heuristic.hpp"

std::atomic<bool> stop_flag(false);
std::atomic<uint64_t> total_count(0);
std::mutex file_mutex;

void signal_handler(int signal)
{
    stop_flag = true;
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

// Batch size for reducing lock contention
constexpr int BATCH_SIZE = 1000;

// tweak value corresponding to private_key += 1 (big‑endian scalar)
static const uint8_t tweak_one[32] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
};

void worker_function()
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx)
        return;

    std::random_device rd;
    std::seed_seq seq{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
    std::mt19937_64 rng;
    rng.seed(seq);

    // Pre-allocated buffers
    uint8_t private_key[32];
    uint8_t pubkey_ser[65];
    uint8_t hash[32];
    uint8_t wallet_address[20];
    char addr_hex[41]; // 40 hex chars + null terminator
    addr_hex[40] = '\0';

    // Local buffer for batch results
    struct LocalResult
    {
        int score;
        char addr[41];
        char priv_key[65];
    };
    std::vector<LocalResult> local_results;
    local_results.reserve(16);

    int local_count = 0;

    // iteration counter for reseeding
    int iter = 0;
    constexpr int RESEED_INTERVAL = 1'000'000;

    secp256k1_pubkey pubkey;

    // lambda to generate a new random key pair
    auto reseed = [&]() {
        do {
            for (int k = 0; k < 4; ++k)
                reinterpret_cast<uint64_t *>(private_key)[k] = rng();
        } while (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key));
        iter = 0;
    };

    // start with a fresh random key
    reseed();

    while (!stop_flag)
    {
        // serialize and hash the current public key
        size_t pubkey_len = sizeof(pubkey_ser);
        secp256k1_ec_pubkey_serialize(ctx, pubkey_ser, &pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        keccak256(pubkey_ser + 1, 64, hash);
        memcpy(wallet_address, hash + 12, 20);

        std::string checksum_addr = to_checksum_address(wallet_address);
        int score = main_heuristic(checksum_addr.c_str());

        if (score > 50)
        {
            LocalResult res;
            res.score = score;
            memcpy(res.addr, checksum_addr.c_str(), 41);
            to_hex_fast(private_key, 32, res.priv_key);
            res.priv_key[64] = '\0';
            local_results.push_back(res);
        }

        local_count++;

        // advance to next key: increment scalar and tweak the pubkey
        for (int i = 31; i >= 0; --i)
        {
            if (++private_key[i] != 0)
                break;
        }
        if (!secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, tweak_one))
        {
            // extremely unlikely (point at infinity) – just reseed
            reseed();
        }

        if (++iter >= RESEED_INTERVAL)
            reseed();

        // Batch update counters and write results
        if (local_count >= BATCH_SIZE)
        {
            total_count.fetch_add(local_count, std::memory_order_relaxed);
            local_count = 0;

            if (!local_results.empty())
            {
                std::lock_guard<std::mutex> lock(file_mutex);
                std::ofstream file("PrettyAddresses.csv", std::ios::app);
                for (const auto &res : local_results)
                {
                    file << res.score << "," << res.addr << "," << res.priv_key << "\n";
                }
                local_results.clear();
            }
        }
    }

    // Final flush
    total_count.fetch_add(local_count, std::memory_order_relaxed);
    if (!local_results.empty())
    {
        std::lock_guard<std::mutex> lock(file_mutex);
        std::ofstream file("PrettyAddresses.csv", std::ios::app);
        for (const auto &res : local_results)
        {
            file << res.score << "," << res.addr << "," << res.priv_key << "\n";
        }
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
    // num_threads = std::thread::hardware_concurrency() / 2 - 1;
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
    uint64_t last_count = 0;
    while (!stop_flag)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto current_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = current_time - start_time;
        uint64_t current_count = total_count.load(std::memory_order_relaxed);
        double avg_speed = current_count / elapsed.count();
        double instant_speed = current_count - last_count;  // per second
        last_count = current_count;
        std::cout << "\rGenerated " << current_count << " addresses | Avg: "
                  << std::fixed << std::setprecision(0) << avg_speed
                  << " addr/s | Current: " << instant_speed << " addr/s    " << std::flush;
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
        int new_score = main_heuristic(addr.c_str());
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
