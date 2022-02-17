// Copyright (c) 2019-2022, The Vulkan Developers.
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

#include <stdlib.h>
#include <stdint.h>

#include "common/vulkan.h"

VULKAN_BEGIN_DECL

#define BLOCK_VERSION 0x01
#define MAX_BLOCK_SIZE (1024 * 1024 * 512) // 512mb
#define MAX_TX_SIZE (1024 * 512) // 512kb
#define MAX_FUTURE_BLOCK_TIME (60 * 60 * 2)
#define TIMESTAMP_CHECK_WINDOW 32

#define COIN ((uint64_t)100000000)
#define TOTAL_SUPPLY 64000000
#define MAX_MONEY ((uint64_t)(COIN * TOTAL_SUPPLY))

#define MAINNET_ADDRESS_ID 0x01
#define TESTNET_ADDRESS_ID 0x02

#define GENESIS_NONCE 0
#define GENESIS_BITS 0
#define GENESIS_TIMESTAMP 0
#define GENESIS_REWARD ((uint64_t)0)

#define TESTNET_GENESIS_NONCE 2273200037
#define TESTNET_GENESIS_BITS 486604799
#define TESTNET_GENESIS_TIMESTAMP 1645119298
#define TESTNET_GENESIS_REWARD ((uint64_t)0)

#define MEMPOOL_TX_EXPIRE_TIME (60 * 60 * 24)

#define POW_TARGET_TIMESPAN (60 * 60 * 10)
#define POW_TARGET_SPACING (1 * 60)
#define POW_INITIAL_DIFFICULTY_BITS 0x1d00ffff

#define BLOCK_REWARD_EMISSION_FACTOR 20

#define P2P_PORT 9899
#define RPC_PORT 9898

#define TESTNET_P2P_PORT 8899
#define TESTNET_RPC_PORT 8898

#define MAX_P2P_PEERS_COUNT 16
#define MAX_GROUPED_BLOCKS_COUNT 6

#define DEFAULT_COMPACTION_MEMTABLE_MEMORY_BUDGET (1024 * 1024 * 512) // 512mb

VULKAN_API void parameters_set_use_testnet(int use_testnet);
VULKAN_API const int parameters_get_use_testnet(void);

VULKAN_API const uint8_t parameters_get_address_id(void);

VULKAN_API const uint32_t parameters_get_genesis_nonce(void);
VULKAN_API const uint32_t parameters_get_genesis_bits(void);
VULKAN_API const uint32_t parameters_get_genesis_timestamp(void);
VULKAN_API const uint64_t parameters_get_genesis_reward(void);

VULKAN_API const uint64_t parameters_get_pow_target_timespan(void);
VULKAN_API const uint64_t parameters_get_pow_target_spacing(void);
VULKAN_API const uint64_t parameters_get_difficulty_adjustment_interval(void);
VULKAN_API const uint32_t parameters_get_pow_initial_difficulty_bits(void);

VULKAN_API const uint16_t parameters_get_p2p_port(void);
VULKAN_API const uint16_t parameters_get_rpc_port(void);

VULKAN_API const int parameters_get_allow_min_difficulty_blocks(void);

VULKAN_END_DECL
