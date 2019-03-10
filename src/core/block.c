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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <sodium.h>

#include "common/logger.h"
#include "common/buffer.h"
#include "common/util.h"

#include "block.h"
#include "blockchainparams.h"
#include "difficulty.h"
#include "merkle.h"

#include "crypto/sha256d.h"

/* Allocates a block for usage.
 *
 * Later to be free'd with `free_block`
 */
block_t* make_block(void)
{
  block_t *block = malloc(sizeof(block_t));

  block->version = BLOCK_VERSION;

  memset(block->previous_hash, 0, HASH_SIZE);
  memset(block->hash, 0, HASH_SIZE);

  block->timestamp = 0;
  block->nonce = 0;
  block->difficulty = 0;
  block->cumulative_difficulty = 0;
  block->already_generated_coins = 0;

  memcpy(block->merkle_root, &genesis_block.merkle_root, HASH_SIZE);
  block->transaction_count = 0;
  block->transactions = NULL;

  return block;
}

int hash_block(block_t *block)
{
  assert(block != NULL);

  buffer_t *buffer = buffer_init_size(0, BLOCK_HEADER_SIZE);
  serialize_block_header(buffer, block);

  uint8_t header[BLOCK_HEADER_SIZE];
  memcpy(header, buffer->data, BLOCK_HEADER_SIZE);

  buffer_free(buffer);
  crypto_hash_sha256d(block->hash, header, BLOCK_HEADER_SIZE);
  return 0;
}

int valid_block_timestamp(block_t *block)
{
  assert(block != NULL);
  if (block->timestamp > get_current_time() + MAX_FUTURE_BLOCK_TIME)
  {
    return 0;
  }

  return 1;
}

// Block is valid if:
// - Timestamp is stamped for a 2 hour drift
// - The first TX is a generational TX
// - TXs don't share any hash IDs
// - TXs don't have any same TXINs referencing the same txout + id
// - TXs TXINs reference UXTOs
// - The block hash is valid
// - The merkle root is valid
//
// Returns 0 if invalid, 1 is valid.
int valid_block(block_t *block)
{
  assert(block != NULL);

  // block timestamp must be less than or equal to current_target + MAX_FUTURE_BLOCK_TIME
  if (!valid_block_timestamp(block))
  {
    LOG_DEBUG("Block has timestamp that is too far in the future: %d!", block->timestamp);
    return 0;
  }

  // block must have a non-zero number of TXs.
  if (block->transaction_count < 1)
  {
    return 0;
  }

  // first TX must always be a generational TX.
  if (!is_generation_tx(block->transactions[0]))
  {
    return 0;
  }

  // For each TX, compare to the other TXs that:
  // - No other TX shares the same hash id
  // - No other TX shares the same TXIN referencing the same txout + id
  for (int first_tx_index = 0; first_tx_index < block->transaction_count; first_tx_index++)
  {
    transaction_t *first_tx = block->transactions[first_tx_index];
    assert(first_tx != NULL);

    // check to see if we have more than one generational transaction
    if (first_tx_index != 0 && is_generation_tx(first_tx))
    {
      return 0;
    }

    // check to see if this is a valid transaction
    if (!valid_transaction(first_tx))
    {
      return 0;
    }

    for (int second_tx_index = 0; second_tx_index < block->transaction_count; second_tx_index++)
    {
      transaction_t *second_tx = block->transactions[second_tx_index];
      assert(second_tx != NULL);

      if (first_tx_index == second_tx_index)
      {
        continue;
      }

      // check to see if any transactions have duplicate transaction hash ids
      if (compare_transaction_hash(first_tx->id, second_tx->id))
      {
        return 0;
      }

      // check to see if any transactions reference same txout id + index
      for (int first_txin_index = 0; first_txin_index < block->transactions[first_tx_index]->txin_count; first_txin_index++)
      {
        input_transaction_t *txin_first = first_tx->txins[first_tx_index];
        assert(txin_first != NULL);

        for (int second_txin_index = 0; second_txin_index < block->transactions[second_tx_index]->txin_count; second_txin_index++)
        {
          input_transaction_t *txin_second = second_tx->txins[second_txin_index];
          assert(txin_second != NULL);

          if (compare_transaction_hash(txin_first->transaction, txin_second->transaction) && txin_first->txout_index == txin_second->txout_index)
          {
            return 0;
          }
        }
      }
    }
  }

  // check to ensure that the block header size is less than the
  // maximum allowed block size...
  uint32_t block_header_size = get_block_header_size(block);
  if (block_header_size > MAX_BLOCK_SIZE)
  {
    LOG_DEBUG("Block has too big header blob size: %d!", block_header_size);
    return 0;
  }

  // check the block hash
  if (!valid_block_hash(block))
  {
    return 0;
  }

  // check the merkle root
  if (!valid_merkle_root(block))
  {
    return 0;
  }

  return 1;
}

int valid_merkle_root(block_t *block)
{
  assert(block != NULL);
  uint8_t *merkle_root = malloc(sizeof(uint8_t*) * HASH_SIZE);
  compute_merkle_root(merkle_root, block);

  if (compare_merkle_hash(merkle_root, block->merkle_root))
  {
    return 1;
  }
  else
  {
    return 0;
  }
}

int compute_merkle_root(uint8_t *merkle_root, block_t *block)
{
  assert(block != NULL);
  uint8_t *hashes = malloc(sizeof(uint8_t*) * HASH_SIZE * block->transaction_count);
  for (int i = 0; i < block->transaction_count; i++)
  {
    compute_tx_id(&hashes[HASH_SIZE * i], block->transactions[i]);
  }

  merkle_tree_t *tree = construct_merkle_tree_from_leaves(hashes, block->transaction_count);
  memcpy(merkle_root, tree->root->hash, HASH_SIZE);

  free_merkle_tree(tree);
  free(hashes);
  return 0;
}

int compute_self_merkle_root(block_t *block)
{
  assert(block != NULL);
  compute_merkle_root(block->merkle_root, block);
  return 0;
}

int print_block(block_t *block)
{
  assert(block != NULL);

  printf("Block:\n");
  printf("Version: %d\n", block->version);
  printf("Nonce: %d\n", block->nonce);
  printf("Timestamp (epoch): %d\n", block->timestamp);
  printf("Difficulty: %llu\n", block->difficulty);
  printf("Cumulative Difficulty: %llu\n", block->cumulative_difficulty);
  printf("Emission: %llu\n", block->already_generated_coins);
  printf("Previous Hash: %s\n", hash_to_str(block->previous_hash));
  printf("Merkle Root: %s\n", hash_to_str(block->merkle_root));
  printf("Hash: %s\n", hash_to_str(block->hash));

  return 0;
}

int valid_block_hash(block_t *block)
{
  assert(block != NULL);
  return check_hash(block->hash, block->difficulty);
}

uint32_t get_block_header_size(block_t *block)
{
  assert(block != NULL);
  uint32_t block_header_size = BLOCK_HEADER_SIZE;
  for (int i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);
    block_header_size += get_tx_header_size(tx);
  }

  return block_header_size;
}

int compare_block_hash(uint8_t *hash, uint8_t *other_hash)
{
  return memcmp(hash, other_hash, HASH_SIZE) == 0;
}

int compare_block(block_t *block, block_t *other_block)
{
  assert(block != NULL);
  assert(other_block != NULL);
  return (compare_block_hash(block->hash, other_block->hash) && compare_merkle_hash(block->merkle_root, other_block->merkle_root));
}

int compare_with_genesis_block(block_t *block)
{
  assert(block != NULL);

  hash_block(block);
  hash_block(&genesis_block);

  return compare_block(block, &genesis_block);
}

int serialize_block_header(buffer_t *buffer, block_t *block)
{
  assert(block != NULL);
  assert(buffer != NULL);

  buffer_write_uint32(buffer, block->version);
  buffer_write_uint32(buffer, block->nonce);
  buffer_write_uint32(buffer, block->timestamp);
  buffer_write_uint64(buffer, block->difficulty);
  buffer_write_uint64(buffer, block->cumulative_difficulty);
  buffer_write_uint64(buffer, block->already_generated_coins);

  // write raw hash's
  buffer_write(buffer, block->previous_hash, HASH_SIZE);
  buffer_write(buffer, block->merkle_root, HASH_SIZE);
  return 0;
}

int serialize_block(buffer_t *buffer, block_t *block)
{
  assert(block != NULL);
  assert(buffer != NULL);

  buffer_write_uint32(buffer, block->version);

  buffer_write_bytes(buffer, block->previous_hash, HASH_SIZE);
  buffer_write_bytes(buffer, block->hash, HASH_SIZE);

  buffer_write_uint32(buffer, block->timestamp);
  buffer_write_uint32(buffer, block->nonce);
  buffer_write_uint64(buffer, block->difficulty);
  buffer_write_uint64(buffer, block->cumulative_difficulty);
  buffer_write_uint64(buffer, block->already_generated_coins);

  buffer_write_bytes(buffer, block->merkle_root, HASH_SIZE);
  buffer_write_uint32(buffer, block->transaction_count);
  return 0;
}

block_t* deserialize_block(buffer_t *buffer)
{
  assert(buffer != NULL);

  block_t *block = make_block();
  assert(block != NULL);

  block->version = buffer_read_uint32(buffer);

  uint8_t *previous_hash = buffer_read_bytes(buffer);
  memcpy(block->previous_hash, previous_hash, HASH_SIZE);

  uint8_t *hash = buffer_read_bytes(buffer);
  memcpy(block->hash, hash, HASH_SIZE);

  block->timestamp = buffer_read_uint32(buffer);
  block->nonce = buffer_read_uint32(buffer);
  block->difficulty = buffer_read_uint64(buffer);
  block->cumulative_difficulty = buffer_read_uint64(buffer);
  block->already_generated_coins = buffer_read_uint64(buffer);

  uint8_t *merkle_root = buffer_read_bytes(buffer);
  memcpy(block->merkle_root, merkle_root, HASH_SIZE);

  block->transaction_count = buffer_read_uint32(buffer);

  free(previous_hash);
  free(hash);
  free(merkle_root);

  return block;
}

int block_to_serialized(uint8_t **data, uint32_t *data_len, block_t *block)
{
  assert(block != NULL);
  buffer_t *buffer = buffer_init();
  if (serialize_block(buffer, block))
  {
    return 1;
  }

  *data_len = buffer_get_size(buffer);
  *data = malloc(*data_len);

  memcpy(*data, buffer->data, *data_len);
  buffer_free(buffer);

  return 0;
}

block_t* block_from_serialized(uint8_t *data, uint32_t data_len)
{
  buffer_t *buffer = buffer_init_data(0, (const uint8_t*)data, data_len);
  block_t *block = deserialize_block(buffer);
  buffer_free(buffer);
  return block;
}

int serialize_transactions_from_block(buffer_t *buffer, block_t *block)
{
  assert(buffer != NULL);
  assert(block != NULL);

  for (int i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);

    if (serialize_transaction(buffer, tx))
    {
      return 1;
    }
  }

  return 0;
}

int deserialize_transactions_to_block(buffer_t *buffer, block_t *block)
{
  assert(buffer != NULL);
  assert(block != NULL);

  block->transactions = malloc(sizeof(transaction_t) * block->transaction_count);
  for (int i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = deserialize_transaction(buffer);
    assert(tx != NULL);
    block->transactions[i] = tx;
  }

  return 0;
}

/*
 * Frees an allocated block, and its corresponding TXs.
 */
int free_block(block_t *block)
{
  assert(block != NULL);
  if (block->transaction_count > 0 && block->transactions != NULL)
  {
    for (int i = 0; i < block->transaction_count; i++)
    {
      transaction_t *tx = block->transactions[i];
      assert(tx != NULL);
      free_transaction(tx);
    }

    free(block->transactions);
  }

  free(block);
  return 0;
}
