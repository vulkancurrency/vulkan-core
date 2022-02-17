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

/* MAINNET genesis block info: */
static const output_transaction_genesis_entry_t mainnet_genesis_output_txs[] = {
  {
    .amount = 6103515625,
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
  .cumulative_emission = 6103515625,
  .merkle_root_str = "0000000000000000000000000000000000000000000000000000000000000000",
};

/* TESTNET genesis block info: */
static const output_transaction_genesis_entry_t testnet_genesis_output_txs[] = {
  {
    .amount = 6103515625,
    .address_str = "0232dbc228de4cf289a242758eb942361ccbf6ff6fc404793cdb47ad61dac2dc1c"
  }
};

static const transaction_genesis_entry_t testnet_genesis_tx = {
  .id_str = "2e14eb0db055d9ad1951dafde363eac845d4903e93367481b6576efdc8bfafac"
};

static const block_genesis_entry_t testnet_genesis_block_template = {
  .version = BLOCK_VERSION,
  .previous_hash_str = "0000000000000000000000000000000000000000000000000000000000000000",
  .hash_str = "00000000ca2796715a7515bf51295cce6715d6a6dfafe67effab4e2a7798423f",
  .timestamp = TESTNET_GENESIS_TIMESTAMP,
  .nonce = TESTNET_GENESIS_NONCE,
  .bits = TESTNET_GENESIS_BITS,
  .cumulative_emission = 6103515625,
  .merkle_root_str = "2e14eb0db055d9ad1951dafde363eac845d4903e93367481b6576efdc8bfafac",
};

#define NUM_MAINNET_GENESIS_TXOUTS (sizeof(output_transaction_genesis_entry_t) / sizeof(mainnet_genesis_output_txs))
#define NUM_TESTNET_GENESIS_TXOUTS (sizeof(output_transaction_genesis_entry_t) / sizeof(testnet_genesis_output_txs))

VULKAN_API block_t *get_genesis_block(void);

VULKAN_END_DECL
