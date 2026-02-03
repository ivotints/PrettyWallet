#pragma once

constexpr int ADDRESS_LENGTH = 40;

#include <secp256k1.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <stdint.h>
#ifdef __x86_64__
#include <immintrin.h>
#endif
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
