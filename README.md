# PrettyWallet

A high-performance Ethereum address generator that creates "pretty" addresses based on various heuristics like symmetry, repeating characters, sequences, and vanity words.

## Features

- Generates Ethereum-compatible addresses with aesthetic patterns
- Uses multiple heuristics: symmetry, leading/trailing repeats, alternating patterns, sequences, and vanity words
- Multi-threaded for fast generation
- Outputs results to CSV with scores

## Requirements

- C++ compiler (g++ recommended)
- libsecp256k1 library
- pthread support

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
./PrettyWalletGenerator
```

Results are saved to `PrettyAddresses.csv`.

## Usage

The program generates addresses and evaluates them using built-in heuristics. Higher scores indicate "prettier" addresses. Interrupt with Ctrl+C to stop and save results.

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
