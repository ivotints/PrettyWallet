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
