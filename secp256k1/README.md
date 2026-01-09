## secp256k1 Static Library

This folder contains pre-compiled files for Windows (MinGW-w64):
- `secp256k1.h` - header file
- `libsecp256k1.a` - static library

These are all you need to build PrettyWallet on Windows.

---

## Rebuilding from Source (Optional)

If you want to rebuild the static library yourself:

### Prerequisites

Open **MSYS2 MinGW64** terminal and install:

```sh
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake git
```

### Build Steps

```sh
# Clone secp256k1 source
git clone https://github.com/bitcoin-core/secp256k1.git secp256k1_src
cd secp256k1_src

# Create build directory
mkdir build && cd build

# Configure with static library
cmake -G "MinGW Makefiles" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    ..

# Build
mingw32-make

# Copy files back
cp src/libsecp256k1.a ../../libsecp256k1.a
cp ../include/secp256k1.h ../../secp256k1.h

# Clean up
cd ../..
rm -rf secp256k1_src
```

The static library is now rebuilt.

