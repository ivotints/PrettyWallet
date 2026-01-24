# PrettyWallet

A high-performance Ethereum address generator that generates and scores thousands of addresses per second to find aesthetically pleasing ones.

## What is PrettyWallet?

PrettyWallet generates Ethereum addresses and evaluates them using multiple heuristics to identify "pretty" addresses—those with desirable patterns like symmetry, repeating digits, sequences, and vanity words. Unlike traditional vanity address generators that require you to specify a prefix or suffix upfront, PrettyWallet generates a large pool of addresses and lets you pick from the highest-scoring results based on various aesthetic criteria.

Running on consumer hardware, it generates hundreds of thousands of addresses per second, quickly building a curated collection of visually interesting addresses you can choose from.

## Features

- Generates Ethereum-compatible addresses with aesthetic patterns
- Uses multiple heuristics: symmetry, leading/trailing repeats, alternating patterns, sequences, and vanity words
- Multi-threaded for fast generation (272k+ addresses/sec on 6-core systems)
- Outputs scored results to CSV for easy browsing
- Platform-agnostic (Linux and Windows support)

## Requirements

- C++ compiler (g++ recommended)
- libsecp256k1 library
- pthread support

## Project Structure

- `src/`: Source code files (main.cpp, vanity.cpp, heuristic.cpp, keccak.cpp)
- `include/`: Header files
- `build/`: Build output directory
- `deps/`: Platform-specific dependencies (libsecp256k1)

## Build

```bash
make
```

## Run

```bash
make run
```

Or directly:

```bash
./build/PrettyWalletGenerator
```

Results are saved to `PrettyAddresses.csv`.

## Usage

The program generates addresses and evaluates them using built-in heuristics. Higher scores indicate "prettier" addresses. Interrupt with Ctrl+C to stop and save results.

## Performance

On a 6-core laptop, the generator achieves around 272,000 addresses per second:

```
./build/PrettyWalletGenerator
Generated 11996000 addresses | Avg: 272585 addr/s | Current: 267000 addr/s
```

For comparison, online tools like vanity-eth.tk generate at about 9,000 addresses per second but focus on specific prefix/suffix vanity addresses. PrettyWallet provides a large pool of aesthetically pleasing addresses scored by multiple heuristics, giving you more variety and choice.

## Example Output

The generated addresses are saved to `PrettyAddresses.csv` in CSV format: `score,address,private_key`

Example entries:

```
578,9999999FcE889D3a2de60029d989034d5c0D2999,f650e4ab520ce57fab9095d3f73f7060f84b6bb4eb7a2dc6d21e516d53241aba
532,3339a3127abA1a1EF61b2bF165c71Ab243333333,ad97d266e2e64bf52b06c8feac1f6ad65716c1afcae3dd19f7281683728ff1dc
512,0123205c59d64e112Cb63EE0452aA39dB2345678,b5e1156bcdca179feefe7a53aaa134d3a8a61d30f9350311ac3d8cf7e190b29e
512,FEdCba9FC5f5BA1F5ed05d3Dae2dAc672D2e789a,0c60b331d36af4a8efe9a80df24b600940dde811d3c732505d749cc7f0961f88
512,bCD6bA46B90C8D1b35c660878472378687654321,cd5ef0115eeb840b5c7c5a092d1fd725271ad89a68e377d29ca26c2e53ae033b
```
