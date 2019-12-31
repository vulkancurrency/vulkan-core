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

#include <stdlib.h>
#include <stdint.h>

#include "common/vulkan.h"

#include "block.h"
#include "transaction.h"

VULKAN_BEGIN_DECL

typedef struct InputTransactionGenesisEntry
{
  char *transaction_str;
  uint32_t txout_index;

  char *signature_str;
  char *public_key_str;
} input_transaction_genesis_entry_t;

typedef struct OutputTransactionGenesisEntry
{
  uint64_t amount;
  char *address_str;
} output_transaction_genesis_entry_t;

typedef struct TransactionGenesisEntry
{
  char *id_str;
} transaction_genesis_entry_t;

typedef struct BlockGenesisEntry
{
  uint32_t version;

  char *previous_hash_str;
  char *hash_str;

  uint32_t timestamp;
  uint32_t nonce;
  uint32_t bits;
  uint64_t cumulative_emission;

  char *merkle_root_str;
} block_genesis_entry_t;

// mainnnet genesis block info
static const output_transaction_genesis_entry_t mainnet_genesis_output_txs[] = {
  {
    .amount = 0,
    .address_str = "000000000000000000000000000000000000000000000000000000000000000000"
  }
};

static const transaction_genesis_entry_t mainnet_genesis_tx = {
  .id_str = "0000000000000000000000000000000000000000000000000000000000000000"
};

static const block_genesis_entry_t mainnet_genesis_block_template = {
  .version = BLOCK_VERSION,
  .previous_hash_str = "0000000000000000000000000000000000000000000000000000000000000000",
  .hash_str = "0000000000000000000000000000000000000000000000000000000000000000",
  .timestamp = GENESIS_TIMESTAMP,
  .nonce = GENESIS_NONCE,
  .bits = GENESIS_BITS,
  .cumulative_emission = 0,
  .merkle_root_str = "0000000000000000000000000000000000000000000000000000000000000000",
};

// testnet genesis block info
static const output_transaction_genesis_entry_t testnet_genesis_output_txs[] = {
  {
    .amount = 6103515625,
    .address_str = "0294aaa5c230304920bf88f928523c32b9301f2d48a4e9f2a19c81e5a91ee14b9b"
  }
};

static const transaction_genesis_entry_t testnet_genesis_tx = {
  .id_str = "445b6fc088a96b7a97ed50b3ec137d827a8983689aed05de88cfd6827c4cd668"
};

static const block_genesis_entry_t testnet_genesis_block_template = {
  .version = BLOCK_VERSION,
  .previous_hash_str = "0000000000000000000000000000000000000000000000000000000000000000",
  .hash_str = "0000000094ca6c8e60b5a48f7d0afb3e92b56d023edd880f88c888c21c96e1c9",
  .timestamp = TESTNET_GENESIS_TIMESTAMP,
  .nonce = TESTNET_GENESIS_NONCE,
  .bits = TESTNET_GENESIS_BITS,
  .cumulative_emission = 6103515625,
  .merkle_root_str = "445b6fc088a96b7a97ed50b3ec137d827a8983689aed05de88cfd6827c4cd668",
};

#define NUM_MAINNET_GENESIS_TXOUTS (sizeof(output_transaction_genesis_entry_t) / sizeof(mainnet_genesis_output_txs))
#define NUM_TESTNET_GENESIS_TXOUTS (sizeof(output_transaction_genesis_entry_t) / sizeof(testnet_genesis_output_txs))

VULKAN_API block_t *get_genesis_block(void);

VULKAN_END_DECL
