
# Vulkan Cryptocurrency

## Overview
Vulkan is a robust, high-performance cryptocurrency blockchain designed for efficiency and scalability. It is developed in C with Python bindings using Cython, making it versatile for various platforms including macOS, Windows, Android, and embedded devices. Vulkan leverages RocksDB/LevelDB for optimized data storage, thus reducing reliance on RAM and enhancing performance through better disk space utilization.

## Features
- **Lightweight and Fast:** Tailored for speed and low resource consumption.
- **Cross-Platform:** Runs on macOS, Windows, Android, and embedded systems.
- **Advanced Storage:** Uses RocksDB/LevelB to optimize the storage of blockchain data.

## Current Implementations
- **SHA256 Proof of Work (PoW):** Adopts the same SHA256 PoW as Bitcoin.
- **Proof of Activity (PoA):** Future updates will include PoA to evolve the project further.

## Installation Guide

### Dependencies
Vulkan comes with necessary submodules in the `external` directory. You can install precompiled dependencies to reduce setup time.

#### Windows
- Detailed setup instructions will be added soon.

#### macOS
Use `Homebrew` to install the following packages:
- `brew install leveldb`
- `brew install rocksdb`
- `brew install libsodium`

#### Linux
Use `apt-get` to install the following packages:
- `sudo apt-get install librocksdb-dev`
- `sudo apt-get install libsodium-dev`

## Compilation Instructions
After installing dependencies, use CMake to compile the Vulkan daemon. Follow these platform-specific instructions:

### Windows
```bash
git clone https://github.com/vulkancurrency/vulkan.git
cd vulkan
git submodule update --init --recursive
mkdir build
cd build
cmake -G "Visual Studio 14 Win64" ..
```

### macOS & Linux
```bash
git clone https://github.com/vulkancurrency/vulkan.git
cd vulkan
git submodule update --init --recursive
mkdir build
cd build
cmake .. && make -j 4
```

### ARM MacBook
```bash
arch -x86_64 /usr/local/bin/cmake ..
make -j NUMBER_OF_THREADS_HERE
```

## Forking Guide
Forking Vulkan is encouraged to help evolve the project.

### Steps to Fork:
1. **Update `parameters.h`** - Adjust definitions for either testnet or mainnet.
2. **Recompile** - Build the daemon and create a genesis block.
3. **Update Configurations** - Adjust the genesis block outputs in the config files.

## Testnet Genesis Block Example
```plaintext
Block:
Version: 1
Previous Hash: 0000000000000000000000000000000000000000000000000000000000000000
Hash: 00000000ca2796715a7515bf51295cce6715d6a6dfafe67effab4e2a7798423f
...
```

## License
Vulkan is distributed under the MIT License. For more details, see the LICENSE file.
