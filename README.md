<img src="https://github.com/vulkancurrency/vulkan-resources/raw/master/images/misc/Screen%20Shot%202022-02-13%20at%2011.05.25%20PM.png" align="right" width="600">

# Vulkan

Vulkan is a light weight, fast and efficient cryptocurrency blockchain implementation written in C11. The Vulkan Currency core implementation is embedded and runs on Mac OS, Windows, Android and other embedded devices. Vulkan Currency is designed around scalability and utilizes RocksDB/LevelDB to store and retrieve blockchain information including transaction memory pool data, effectively shifting limitations from available RAM (Random Access Memory) to available disk space. Performance limitations to physical disk storage devices are a limiting factor to the performance of the implementation when connected to the Vulkan network. The Vulkan core project currently utilizes the same [SHA256 POW (Proof of Work)](https://en.bitcoin.it/wiki/Proof_of_work) that is implemented in the [Bitcoin Core](https://github.com/bitcoin/bitcoin) implementation, however a POA (Proof of Activity) concept is in the works and will be implemented as the project inherently evolves.

# Coverage

| Type      | Status |
|-----------|--------|
| Coverity  | [![Coverity Status](https://scan.coverity.com/projects/20120/badge.svg)](https://scan.coverity.com/projects/20120/)

# Installing Dependencies

This project comes included with submodules located in the `external` directory of the project root source code directory which contains the source code repositories for the dependencies necessary to compile the Vulkan Currency daemon, you can also install precompiled dependencies (which decreases your overall compile time) or you can just have the CMake build files build the dependency source code as mentioned earlier.

To manually install some of the dependencies required by the Vulkan Project, you can follow the information below for your specific platform:

## Windows

TODO

## Mac OS

Install the following packages using the `Homebrew` package manager:

### Installing LevelDB

```
brew install leveldb
```

### Installing RocksDB

```
brew install rocksdb
```

### Installing LibSodium

```
brew install libsodium
```

### Linux

Install the following packages using the `apt-get` package manager:

### Installing LevelDB

```
sudo apt-get install libsodium-dev
```

### Installing RocksDB

```
sudo apt-get install librocksdb-dev
```

### Installing LibSodium

```
sudo apt-get install libsodium-dev
```

# How to compile

After installing all of the dependencies for this project (as specified above), you can compile the Vulkan Currency daemon with the commands below, Vulkan Currency relies on CMake to generate the project build files,
follow the commands below (according to your platform you are running) to compile the daemon implementation provided by this project repository:

## Windows

```
git clone https://github.com/vulkancurrency/vulkan.git
cd vulkan
git submodule update --init --recursive

mkdir build
cd build
cmake -G "Visual Studio 14 Win64" ..
```

## Mac OS & Linux

```
git clone https://github.com/vulkancurrency/vulkan.git
cd vulkan
git submodule update --init --recursive

mkdir build
cd build
cmake .. && make -j 4
```

# Want to fork Vulkan Currency?

PLEASE DO! By all means please do fork Vulkan Currency, we encourage it! The process of forking Vulkan is a very simple one.

## Step #1 - Update parameters.h
### Choose testnet and/or mainnet and update the following definitions:

#### Mainnet
```
#define GENESIS_NONCE 0
#define GENESIS_BITS 0
#define GENESIS_TIMESTAMP 0
#define GENESIS_REWARD ((uint64_t)0)
```

#### Testnet
```
#define TESTNET_GENESIS_NONCE 2691906045
#define TESTNET_GENESIS_BITS 0x1d00ffff
#define TESTNET_GENESIS_TIMESTAMP 0
#define TESTNET_GENESIS_REWARD ((uint64_t)0)
```

## Step #2 - Recompile the daemon and run the following commands:

### Mainnet
```
./vulkan --worker-threads 2 --create-genesis-block --mine
```

### Testnet
```
./vulkan --testnet --worker-threads 2 --create-genesis-block --mine
```

## Step #3 - Take the genesis block output written to stdout and update the variables defined in the parameters.h file and the genesis.h file (take into account if you are using testnet or mainnet)

## Congratulations, you have successfully forked Vulkan Currency!

# License

Vulkan is licensed under the "MIT License" for more info, refer to the [LICENSE](LICENSE) file.
