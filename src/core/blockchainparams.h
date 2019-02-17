// Copyright (c) 2019, The Vulkan Developers.
//
// This file is part of Vulkan.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// You should have received a copy of the MIT License
// along with Vulkan. If not, see <https://opensource.org/licenses/MIT>.

#pragma once

#include <stdint.h>

#define BLOCK_VERSION 0x01
#define MAX_BLOCK_SIZE 500000000
#define MAX_TX_SIZE (MAX_BLOCK_SIZE / 2)
#define MAX_FUTURE_BLOCK_TIME (60 * 60 * 2)
#define TIMESTAMP_CHECK_WINDOW 32

#define COIN ((uint64_t)100000000)
#define TOTAL_SUPPLY 64000000
#define MAX_MONEY ((uint64_t)(COIN * TOTAL_SUPPLY))

#define MAINNET_ADDRESS_ID 0x01
#define TESTNET_ADDRESS_ID 0x02

#define GENESIS_NONCE 0
#define GENESIS_TIMESTAMP 1504395525
#define GENESIS_REWARD ((uint64_t)0)

#define MEMPOOL_TX_EXPIRE_TIME (60 * 60 * 24)

#define TIME_BETWEEN_BLOCKS_IN_SECS_TARGET (1 * 60)
#define DIFFICULTY_PERIOD_IN_SECS_TARGET (60 * 60 * 10)
#define DIFFICULTY_PERIOD_IN_BLOCKS_TARGET (DIFFICULTY_PERIOD_IN_SECS_TARGET / TIME_BETWEEN_BLOCKS_IN_SECS_TARGET)
#define INITIAL_DIFFICULTY_BITS 85

#define BLOCK_REWARD_EMISSION_FACTOR 18

#define P2P_PORT 9899
#define RPC_PORT 9898

typedef struct SeedNodeEntry
{
  const char *address;
  int port;
} seed_node_entry_t;

static seed_node_entry_t SEED_NODES[] = {
  {"127.0.0.1", P2P_PORT}
};

#define NUM_SEED_NODES (sizeof(SEED_NODES) / sizeof(seed_node_entry_t))
