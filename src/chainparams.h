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

// MAX_BLOCK_SIZE: Max serialized size of a block (1MB)
#define MAX_BLOCK_SIZE 1000000

// MAX_FUTURE_BLOCK_TIME: How far in the future to accept block timestamps (secs)
#define MAX_FUTURE_BLOCK_TIME (60 * 60 * 2)

// COIN: How many fractions to a coin
#define COIN 100000000

// TOTAL_SUPPLY: How many coin that will ever exist
#define TOTAL_SUPPLY 64000000

// MAX_MONEY: Maximum number of coins/units that will ever exist
#define MAX_MONEY (COIN * TOTAL_SUPPLY)

#define MAINNET_ADDRESS_ID 0x01
#define TESTNET_ADDRESS_ID 0x03

// TIME_BETWEEN_BLOCKS_IN_SECS_TARGET: Target duration between blocks being mined (secs)
#define TIME_BETWEEN_BLOCKS_IN_SECS_TARGET (1 * 60)

// DIFFICULTY_PERIOD_IN_SECS_TARGET: How long difficulty should last (secs)
#define DIFFICULTY_PERIOD_IN_SECS_TARGET (60 * 60 * 10)

// DIFFICULTY_PERIOD_IN_BLOCKS_TARGET: How long difficulty should last (blocks)
#define DIFFICULTY_PERIOD_IN_BLOCKS_TARGET (DIFFICULTY_PERIOD_IN_SECS_TARGET / TIME_BETWEEN_BLOCKS_IN_SECS_TARGET)

#define INITIAL_DIFFICULTY_BITS 85

#define HALVE_SUBSIDY_AFTER_BLOCKS_NUM 200000
