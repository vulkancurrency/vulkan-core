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

#include "common/buffer_iterator.h"
#include "common/buffer.h"
#include "common/util.h"

#include "parameters.h"
#include "transaction_builder.h"
#include "transaction.h"

#ifdef __cplusplus
extern "
{
#endif

#define BLOCK_HEADER_SIZE (HASH_SIZE + HASH_SIZE + 8 + 8 + 8 + 4 + 4 + 4)

typedef struct Block
{
  uint32_t version;

  uint8_t previous_hash[HASH_SIZE];
  uint8_t hash[HASH_SIZE];

  uint32_t timestamp;
  uint32_t nonce;
  uint64_t difficulty;
  uint64_t cumulative_difficulty;
  uint64_t cumulative_emission;

  uint8_t merkle_root[HASH_SIZE];
  uint32_t transaction_count;
  transaction_t **transactions;
} block_t;


static block_t genesis_block = {
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
    0xb1, 0x32, 0xc0, 0xdb,
    0x79, 0xb1, 0x6b, 0xc3,
    0xe0, 0x06, 0x01, 0x6c,
    0x0c, 0x99, 0xe6, 0x36,
    0x11, 0x73, 0x63, 0x59,
    0x57, 0xea, 0xa9, 0x2b,
    0x20, 0x9c, 0x49, 0x6b,
    0x8b, 0x89, 0x1e, 0xcc
  },
  .timestamp = GENESIS_TIMESTAMP,
  .nonce = GENESIS_NONCE,
  .difficulty = 1,
  .cumulative_difficulty = 1,
  .cumulative_emission = 0,
  .merkle_root = {
    0xf8, 0x99, 0x8c, 0xfc,
    0x83, 0x33, 0x7a, 0x49,
    0xad, 0x80, 0x8b, 0xb9,
    0xf4, 0x92, 0xd6, 0x5e,
    0x4e, 0x18, 0x3a, 0x56,
    0x50, 0xc7, 0x4a, 0x3f,
    0xac, 0x9d, 0x24, 0x9e,
    0x60, 0x4b, 0xf9, 0x52
  },
  .transaction_count = 0,
  .transactions = NULL
};

block_t* make_block(void);

uint32_t get_block_header_size(block_t *block);

int valid_block_hash(block_t *block);
int compare_block_hash(uint8_t *hash, uint8_t *other_hash);
int compare_block(block_t *block, block_t *other_block);

int compare_with_genesis_block(block_t *block);
block_t* compute_genesis_block(wallet_t *wallet);

int valid_block_timestamp(block_t *block);
int valid_block(block_t *block);
int valid_merkle_root(block_t *block);

int compute_merkle_root(uint8_t *merkle_root, block_t *block);
int compute_self_merkle_root(block_t *block);

void print_block(block_t *block);
void print_block_transactions(block_t *block);

int compute_block_hash(uint8_t *hash, block_t *block);
int compute_self_block_hash(block_t *block);

int serialize_block_header(buffer_t *buffer, block_t *block);
int serialize_block(buffer_t *buffer, block_t *block);
int deserialize_block(buffer_iterator_t *buffer_iterator, block_t **block_out);

int block_to_serialized(uint8_t **data, uint32_t *data_len, block_t *block);
block_t* block_from_serialized(uint8_t *data, uint32_t data_len);

int serialize_transactions_from_block(buffer_t *buffer, block_t *block);
int deserialize_transactions_to_block(buffer_iterator_t *buffer_iterator, block_t *block);

int add_transaction_to_block(block_t *block, transaction_t *tx, uint32_t tx_index);
int add_transactions_to_block(block_t *block, transaction_t **transactions, uint32_t num_transactions);
transaction_t* get_tx_by_hash_from_block(block_t *block, uint8_t *tx_hash);
int32_t get_tx_index_from_tx_in_block(block_t *block, transaction_t *tx);

int copy_block_transactions(block_t *block, block_t *other_block);
int copy_block(block_t *block, block_t *other_block);

int free_block_transactions(block_t *block);
int free_block(block_t *block);

#ifdef __cplusplus
}
#endif
