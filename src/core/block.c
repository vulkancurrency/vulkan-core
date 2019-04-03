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
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <sodium.h>

#include "common/logger.h"
#include "common/buffer_iterator.h"
#include "common/buffer.h"
#include "common/util.h"

#include "block.h"
#include "blockchain.h"
#include "parameters.h"
#include "difficulty.h"
#include "merkle.h"

#include "crypto/cryptoutil.h"
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
  block->cumulative_emission = 0;

  memcpy(block->merkle_root, &genesis_block.merkle_root, HASH_SIZE);
  block->transaction_count = 0;
  block->transactions = NULL;

  return block;
}

int valid_block_timestamp(block_t *block)
{
  assert(block != NULL);
  return block->timestamp <= (get_current_time() + MAX_FUTURE_BLOCK_TIME);
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
  if (valid_block_timestamp(block) == 0)
  {
    LOG_DEBUG("Block has timestamp that is too far in the future: %u!", block->timestamp);
    return 0;
  }

  // block must have a non-zero number of TXs.
  if (block->transaction_count < 1)
  {
    return 0;
  }

  // first TX must always be a generational TX.
  if (is_generation_tx(block->transactions[0]) == 0)
  {
    return 0;
  }

  // For each TX, compare to the other TXs that:
  // - No other TX shares the same hash id
  // - No other TX shares the same TXIN referencing the same txout + id
  for (uint32_t first_tx_index = 0; first_tx_index < block->transaction_count; first_tx_index++)
  {
    transaction_t *first_tx = block->transactions[first_tx_index];
    assert(first_tx != NULL);

    // check to see if we have more than one generational transaction
    if (first_tx_index != 0 && is_generation_tx(first_tx))
    {
      return 0;
    }

    // check to see if this is a valid transaction
    if (valid_transaction(first_tx) == 0)
    {
      return 0;
    }

    for (uint32_t second_tx_index = 0; second_tx_index < block->transaction_count; second_tx_index++)
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
      for (uint32_t first_txin_index = 0; first_txin_index < block->transactions[first_tx_index]->txin_count; first_txin_index++)
      {
        input_transaction_t *txin_first = first_tx->txins[first_tx_index];
        assert(txin_first != NULL);

        for (uint32_t second_txin_index = 0; second_txin_index < block->transactions[second_tx_index]->txin_count; second_txin_index++)
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
    LOG_DEBUG("Block has too big header blob size: %u!", block_header_size);
    return 0;
  }

  // check the block hash
  if (valid_block_hash(block) == 0)
  {
    return 0;
  }

  // check the merkle root
  if (valid_merkle_root(block) == 0)
  {
    return 0;
  }

  return 1;
}

int valid_merkle_root(block_t *block)
{
  assert(block != NULL);
  uint8_t merkle_root[HASH_SIZE];
  compute_merkle_root(merkle_root, block);
  return compare_merkle_hash(merkle_root, block->merkle_root);
}

int compute_merkle_root(uint8_t *merkle_root, block_t *block)
{
  assert(block != NULL);
  uint8_t *hashes = malloc(sizeof(uint8_t) * HASH_SIZE * block->transaction_count);
  for (uint32_t i = 0; i < block->transaction_count; i++)
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
  return compute_merkle_root(block->merkle_root, block);
}

void print_block(block_t *block)
{
  assert(block != NULL);

  printf("Block:\n");
  printf("Version: %u\n", block->version);

  printf("Previous Hash: %s\n", hash_to_str(block->previous_hash));
  printf("Hash: %s\n", hash_to_str(block->hash));

  printf("Timestamp (epoch): %u\n", block->timestamp);
  printf("Nonce: %u\n", block->nonce);
  printf("Difficulty: %llu\n", block->difficulty);
  printf("Cumulative Difficulty: %llu\n", block->cumulative_difficulty);
  printf("Cumulative Emission: %llu\n", block->cumulative_emission);

  printf("Merkle Root: %s\n", hash_to_str(block->merkle_root));
  printf("Transaction Count: %u\n", block->transaction_count);
}

void print_block_transactions(block_t *block)
{
  assert(block != NULL);

  for (uint32_t i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);

    print_transaction(tx);
  }
}

int valid_block_hash(block_t *block)
{
  assert(block != NULL);

  // find the expected block hash for this block
  uint8_t expected_block_hash[HASH_SIZE];
  compute_block_hash(expected_block_hash, block);

  // check the expected hash against the block's hash
  // to see if the block has the correct corresponding hash;
  // also check to see if the block's hash target matches
  // it's corresponding proof-of-work difficulty...
  return (compare_block_hash(expected_block_hash, block->hash) && check_pow(block->hash, block->difficulty));
}

int compute_block_hash(uint8_t *hash, block_t *block)
{
  assert(block != NULL);
  buffer_t *buffer = buffer_init_size(0, BLOCK_HEADER_SIZE);
  serialize_block_header(buffer, block);

  uint8_t header[BLOCK_HEADER_SIZE];
  memcpy(header, buffer->data, BLOCK_HEADER_SIZE);

  buffer_free(buffer);
  crypto_hash_sha256d(hash, header, BLOCK_HEADER_SIZE);
  return 0;
}

int compute_self_block_hash(block_t *block)
{
  assert(block != NULL);
  return compute_block_hash(block->hash, block);
}

uint32_t get_block_header_size(block_t *block)
{
  assert(block != NULL);
  uint32_t block_header_size = BLOCK_HEADER_SIZE;
  for (uint32_t i = 0; i < block->transaction_count; i++)
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

  compute_self_block_hash(block);
  compute_self_block_hash(&genesis_block);

  return compare_block(block, &genesis_block);
}

block_t* compute_genesis_block(wallet_t *wallet)
{
  assert(wallet != NULL);

  block_t *block = make_block();
  block->timestamp = GENESIS_TIMESTAMP;
  block->nonce = GENESIS_NONCE;
  block->difficulty = 1;
  block->cumulative_difficulty = 1;

  uint64_t block_reward = get_block_reward(0, 0);
  block->cumulative_emission = block_reward;

  transaction_t *tx = make_generation_tx(wallet, block_reward);
  assert(tx != NULL);
  assert(add_transaction_to_block(block, tx, 0) == 0);

  compute_self_merkle_root(block);
  compute_self_block_hash(block);

  assert(valid_merkle_root(block) == 1);
  assert(valid_block_hash(block) == 1);
  return block;
}

int serialize_block_header(buffer_t *buffer, block_t *block)
{
  assert(block != NULL);
  assert(buffer != NULL);

  buffer_write_uint32(buffer, block->version);
  buffer_write_uint32(buffer, block->timestamp);
  buffer_write_uint32(buffer, block->nonce);
  buffer_write_uint64(buffer, block->difficulty);
  buffer_write_uint64(buffer, block->cumulative_difficulty);
  buffer_write_uint64(buffer, block->cumulative_emission);

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
  buffer_write_uint64(buffer, block->cumulative_emission);

  buffer_write_bytes(buffer, block->merkle_root, HASH_SIZE);
  buffer_write_uint32(buffer, block->transaction_count);
  return 0;
}

int deserialize_block(buffer_iterator_t *buffer_iterator, block_t **block_out)
{
  assert(buffer_iterator != NULL);

  block_t *block = make_block();
  assert(block != NULL);

  if (buffer_read_uint32(buffer_iterator, &block->version))
  {
    return 1;
  }

  uint8_t *previous_hash = NULL;
  if (buffer_read_bytes(buffer_iterator, &previous_hash))
  {
    return 1;
  }

  memcpy(block->previous_hash, previous_hash, HASH_SIZE);
  free(previous_hash);

  uint8_t *hash = NULL;
  if (buffer_read_bytes(buffer_iterator, &hash))
  {
    return 1;
  }

  memcpy(block->hash, hash, HASH_SIZE);
  free(hash);

  if (buffer_read_uint32(buffer_iterator, &block->timestamp))
  {
    return 1;
  }

  if (buffer_read_uint32(buffer_iterator, &block->nonce))
  {
    return 1;
  }

  if (buffer_read_uint64(buffer_iterator, &block->difficulty))
  {
    return 1;
  }

  if (buffer_read_uint64(buffer_iterator, &block->cumulative_difficulty))
  {
    return 1;
  }

  if (buffer_read_uint64(buffer_iterator, &block->cumulative_emission))
  {
    return 1;
  }

  uint8_t *merkle_root = NULL;
  if (buffer_read_bytes(buffer_iterator, &merkle_root))
  {
    return 1;
  }

  memcpy(block->merkle_root, merkle_root, HASH_SIZE);
  free(merkle_root);

  if (buffer_read_uint32(buffer_iterator, &block->transaction_count))
  {
    return 1;
  }

  *block_out = block;
  return 0;
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
  assert(data != NULL);
  buffer_t *buffer = buffer_init_data(0, (const uint8_t*)data, data_len);
  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);

  block_t *block = NULL;
  if (deserialize_block(buffer_iterator, &block))
  {
    buffer_iterator_free(buffer_iterator);
    buffer_free(buffer);
    return NULL;
  }

  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);
  return block;
}

int serialize_transactions_from_block(buffer_t *buffer, block_t *block)
{
  assert(buffer != NULL);
  assert(block != NULL);

  for (uint32_t i = 0; i < block->transaction_count; i++)
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

int deserialize_transactions_to_block(buffer_iterator_t *buffer_iterator, block_t *block)
{
  assert(buffer_iterator != NULL);
  assert(block != NULL);

  if (block->transaction_count > 0)
  {
    block->transactions = malloc(sizeof(transaction_t) * block->transaction_count);

    // deserialize the transactions
    for (uint32_t i = 0; i < block->transaction_count; i++)
    {
      transaction_t *tx = NULL;
      if (deserialize_transaction(buffer_iterator, &tx))
      {
        return 1;
      }

      block->transactions[i] = tx;
    }
  }

  return 0;
}

int add_transaction_to_block(block_t *block, transaction_t *tx, uint32_t tx_index)
{
  assert(block != NULL);
  assert(tx != NULL);

  input_transaction_t *txin = tx->txins[0];
  assert(txin != NULL);

  if (tx_index > 0)
  {
    transaction_t *previous_tx = block->transactions[tx_index - 1];
    assert(previous_tx != NULL);
    memcpy(&txin->transaction, &previous_tx->id, HASH_SIZE);
  }

  if (block->transaction_count == 0 && block->transactions == NULL)
  {
    block->transaction_count = 1;
    block->transactions = malloc(sizeof(transaction_t) * block->transaction_count);
  }
  else
  {
    block->transaction_count++;
    transaction_t **transactions = realloc(block->transactions, sizeof(transaction_t) * block->transaction_count);
    assert(transactions != NULL);
    free(block->transactions);
    block->transactions = transactions;
  }

  block->transactions[tx_index] = tx;
  return 0;
}

int add_transactions_to_block(block_t *block, transaction_t **transactions, uint32_t num_transactions)
{
  assert(block != NULL);
  assert(transactions != NULL);

  for (uint32_t i = 0; i < num_transactions; i++)
  {
    transaction_t *tx = transactions[i];
    assert(tx != NULL);

    // skip over the generation tx
    if (add_transaction_to_block(block, tx, i + 1))
    {
      return 1;
    }
  }

  return 0;
}

transaction_t* get_tx_by_hash_from_block(block_t *block, uint8_t *tx_hash)
{
  assert(block != NULL);
  assert(tx_hash != NULL);

  for (uint32_t i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);

    if (compare_transaction_hash(tx->id, tx_hash))
    {
      return tx;
    }
  }

  return NULL;
}

int32_t get_tx_index_from_tx_in_block(block_t *block, transaction_t *tx)
{
  assert(block != NULL);
  assert(tx != NULL);

  for (uint32_t i = 0; i < block->transaction_count; i++)
  {
    transaction_t *other_tx = block->transactions[i];
    assert(other_tx != NULL);

    if (other_tx == tx)
    {
      return i;
    }
  }

  return -1;
}

int copy_block_transactions(block_t *block, block_t *other_block)
{
  assert(block != NULL);
  assert(other_block != NULL);

  // free old transactions for the block we are copying to
  if (free_block_transactions(other_block))
  {
    return 1;
  }

  if (block->transaction_count > 0 && block->transactions != NULL)
  {
    // allocate the transaction array for the block we are copying to
    other_block->transaction_count = block->transaction_count;
    other_block->transactions = malloc(sizeof(transaction_t) * block->transaction_count);

    // copy the transactions to the block we are copying to
    for (uint32_t i = 0; i < block->transaction_count; i++)
    {
      transaction_t *tx = block->transactions[i];
      assert(tx != NULL);

      transaction_t *other_tx = NULL;
      if (copy_transaction(tx, other_tx))
      {
        return 1;
      }

      assert(other_tx != NULL);
      other_block->transactions[i] = other_tx;
    }
  }

  return 0;
}

int copy_block(block_t *block, block_t *other_block)
{
  assert(block != NULL);
  assert(other_block != NULL);

  other_block->version = block->version;

  memcpy(&other_block->previous_hash, &block->previous_hash, HASH_SIZE);
  memcpy(&other_block->hash, &block->hash, HASH_SIZE);

  other_block->timestamp = block->timestamp;
  other_block->nonce = block->nonce;
  other_block->difficulty = block->difficulty;
  other_block->cumulative_difficulty = block->cumulative_difficulty;
  other_block->cumulative_emission = block->cumulative_emission;

  memcpy(&other_block->merkle_root, &block->merkle_root, HASH_SIZE);
  other_block->transaction_count = block->transaction_count;
  if (copy_block_transactions(block, other_block))
  {
    return 1;
  }

  return 0;
}

int free_block_transactions(block_t *block)
{
  assert(block != NULL);
  if (block->transaction_count > 0 && block->transactions != NULL)
  {
    for (uint32_t i = 0; i < block->transaction_count; i++)
    {
      transaction_t *tx = block->transactions[i];
      assert(tx != NULL);
      if (free_transaction(tx))
      {
        return 1;
      }
    }

    free(block->transactions);
  }

  return 0;
}

/*
 * Frees an allocated block, and its corresponding TXs.
 */
int free_block(block_t *block)
{
  assert(block != NULL);
  if (free_block_transactions(block))
  {
    return 1;
  }

  free(block);
  return 0;
}
