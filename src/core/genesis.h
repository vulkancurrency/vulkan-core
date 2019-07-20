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

static block_t mainnet_genesis_block = {
  .version = BLOCK_VERSION,
  .previous_hash = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  },
  .hash = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  },
  .timestamp = GENESIS_TIMESTAMP,
  .nonce = GENESIS_NONCE,
  .bits = GENESIS_BITS,
  .cumulative_emission = 0,
  .merkle_root = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  },
  .transaction_count = 0,
  .transactions = NULL
};

static const input_transaction_genesis_entry_t testnet_genesis_input_txs[] = {
  {
    .transaction_str = "0000000000000000000000000000000000000000000000000000000000000000",
    .txout_index = 0,
    .signature_str = "bc7378e8a8209ad68aa8ed04d731c383e7a21bbce45dd4cc62c734df38a1851e60e68e64456f7186f6fb168bf015b1b8a8aa5395faa1edc070bce9b5ecc1070f",
    .public_key_str = "2ac12229b9d7255306b0ba77528fcc10ede74befd529c674dd5bb7d7c1358d73"
  }
};

static const output_transaction_genesis_entry_t testnet_genesis_output_txs[] = {
  {
    .amount = 6103515625,
    .address_str = "02bb3d97634bd6a3973cfd1d88450f2cff26a80a76fd18d58afd10a3dca18a85fa"
  }
};

static const transaction_genesis_entry_t testnet_genesis_tx = {
  .id_str = "88bdcdd586bb2a91b627dda8cf2414cdaf0190936a0ba088157096b5bfddbe52"
};

static const block_genesis_entry_t testnet_genesis_block_template = {
  .version = BLOCK_VERSION,
  .previous_hash_str = "0000000000000000000000000000000000000000000000000000000000000000",
  .hash_str = "00000000ff3f568143293e8a701ca6e94ab7c2c686165d685ceb0f918803da45",
  .timestamp = TESTNET_GENESIS_TIMESTAMP,
  .nonce = TESTNET_GENESIS_NONCE,
  .bits = TESTNET_GENESIS_BITS,
  .cumulative_emission = 6103515625,
  .merkle_root_str = "88bdcdd586bb2a91b627dda8cf2414cdaf0190936a0ba088157096b5bfddbe52",
};

static block_t *testnet_genesis_block = NULL;

#define NUM_TESTNET_GENESIS_TXINS (sizeof(input_transaction_genesis_entry_t) / sizeof(testnet_genesis_input_txs))
#define NUM_TESTNET_GENESIS_TXOUTS (sizeof(output_transaction_genesis_entry_t) / sizeof(testnet_genesis_output_txs))

VULKAN_API block_t *get_genesis_block(void);

VULKAN_END_DECL
