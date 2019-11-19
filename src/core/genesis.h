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
    .address_str = "01b15e22c4685cc8b1ea9dfbc575f76c3e6a2774f49a7e68c6668da33337155fab"
  }
};

static const transaction_genesis_entry_t testnet_genesis_tx = {
  .id_str = "5a1f16e7562c87058732764d5a356ad7a30018387be62bb6645e323fc64436a2"
};

static const block_genesis_entry_t testnet_genesis_block_template = {
  .version = BLOCK_VERSION,
  .previous_hash_str = "0000000000000000000000000000000000000000000000000000000000000000",
  .hash_str = "00000000ed7426e21fe6674b75086f7f5ae4cebbd0fad6f56e9bcbf086bb5ad0",
  .timestamp = TESTNET_GENESIS_TIMESTAMP,
  .nonce = TESTNET_GENESIS_NONCE,
  .bits = TESTNET_GENESIS_BITS,
  .cumulative_emission = 6103515625,
  .merkle_root_str = "5a1f16e7562c87058732764d5a356ad7a30018387be62bb6645e323fc64436a2",
};

#define NUM_MAINNET_GENESIS_TXOUTS (sizeof(output_transaction_genesis_entry_t) / sizeof(mainnet_genesis_output_txs))
#define NUM_TESTNET_GENESIS_TXOUTS (sizeof(output_transaction_genesis_entry_t) / sizeof(testnet_genesis_output_txs))

VULKAN_API block_t *get_genesis_block(void);

VULKAN_END_DECL
