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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <rocksdb/c.h>

#include "common/util.h"

#include "block.h"
#include "blockchain.h"
#include "vulkan.pb-c.h"

#include "wallet/wallet.h"

static uint8_t g_blockchain_current_block_hash[HASH_SIZE] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static const char *g_blockchain_dir = NULL;
static const char *g_blockchain_backup_dir = "_backup";

static int g_blockchain_is_open = 0;
static int g_blockchain_backup_is_open = 0;

static rocksdb_t *g_blockchain_db = NULL;
static rocksdb_backup_engine_t *g_blockchain_backup_db = NULL;

const char* get_blockchain_dir(void)
{
  return g_blockchain_dir;
}

const char* get_blockchain_backup_dir(const char *blockchain_dir)
{
  return string_copy(blockchain_dir, g_blockchain_backup_dir);
}

int open_blockchain(const char *blockchain_dir)
{
  if (g_blockchain_is_open)
  {
    return 0;
  }

  g_blockchain_dir = blockchain_dir;

  char *err = NULL;
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(options, 1);

  g_blockchain_db = rocksdb_open(options, blockchain_dir, &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not open blockchain database: %s\n", err);

    rocksdb_free(err);
    rocksdb_free(options);
    return 1;
  }

  if (!has_block_by_hash(genesis_block.hash))
  {
    if (!validate_and_insert_block(&genesis_block))
    {
      fprintf(stderr, "Could not insert genesis block into blockchain!\n");

      rocksdb_free(err);
      rocksdb_free(options);
      return 1;
    }
  }
  else
  {
    block_t *top_block = get_top_block();
    if (!top_block)
    {
      fprintf(stderr, "Could not get unknown blockchain top block!\n");

      rocksdb_free(err);
      rocksdb_free(options);
      return 1;
    }

    set_current_block(top_block);
    free_block(top_block);
  }

  g_blockchain_is_open = 1;

  rocksdb_free(err);
  rocksdb_free(options);
  return 0;
}

int remove_blockchain(const char *blockchain_dir)
{
  if (rmrf(blockchain_dir) != 0)
  {
    return 1;
  }

  const char *blockchain_backup_dir = get_blockchain_backup_dir(blockchain_dir);
  if (rmrf(blockchain_backup_dir) != 0)
  {
    return 1;
  }

  return 0;
}

int close_blockchain(void)
{
  if (!g_blockchain_is_open)
  {
    return 1;
  }

  rocksdb_close(g_blockchain_db);
  g_blockchain_is_open = 0;

  close_backup_blockchain();
  return 0;
}

int open_backup_blockchain(void)
{
  if (g_blockchain_backup_is_open)
  {
    return 1;
  }

  char *err = NULL;
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(options, 1);

  const char *blockchain_backup_dir = get_blockchain_backup_dir(g_blockchain_dir);
  g_blockchain_backup_db = rocksdb_backup_engine_open(options, blockchain_backup_dir, &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not open backup blockchain database: %s\n", err);

    rocksdb_free(err);
    rocksdb_free(options);
    return 1;
  }

  g_blockchain_backup_is_open = 1;

  rocksdb_free(err);
  rocksdb_free(options);
  return 0;
}

int close_backup_blockchain(void)
{
  if (!g_blockchain_backup_is_open)
  {
    return 1;
  }

  rocksdb_backup_engine_close(g_blockchain_backup_db);
  g_blockchain_backup_is_open = 0;
  return 0;
}

int init_blockchain(const char *blockchain_dir)
{
  open_blockchain(blockchain_dir);
  open_backup_blockchain();
  return 0;
}

int backup_blockchain(void)
{
  if (!g_blockchain_backup_is_open)
  {
    return 1;
  }

  char *err = NULL;
  rocksdb_backup_engine_create_new_backup(g_blockchain_backup_db, g_blockchain_db, &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not backup database: %s\n", err);

    rocksdb_free(err);
    return 1;
  }

  rocksdb_free(err);
  return 0;
}

int restore_blockchain(void)
{
  if (!g_blockchain_backup_is_open)
  {
    return 1;
  }

  char *err = NULL;

  rocksdb_restore_options_t *restore_options = rocksdb_restore_options_create();
  rocksdb_backup_engine_restore_db_from_latest_backup(g_blockchain_backup_db, g_blockchain_dir,
    g_blockchain_dir, restore_options, &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not restore database from backup: %s\n", err);

    rocksdb_restore_options_destroy(restore_options);
    rocksdb_free(err);
    return 1;
  }

  rocksdb_restore_options_destroy(restore_options);
  rocksdb_free(err);
  return 0;
}

int rollback_blockchain(uint32_t rollback_height)
{
  uint32_t current_block_height = get_block_height();
  if (rollback_height > current_block_height)
  {
    fprintf(stderr, "Could not rollback blockchain to height: %d, current blockchain top block height is: %d!\n", rollback_height, current_block_height);
    return 1;
  }

  for (uint32_t i = current_block_height; i > 0; i--)
  {
    if (i == rollback_height)
    {
      break;
    }

    block_t *block = get_block_from_height(i);
    if (!block)
    {
      fprintf(stderr, "Could not reset blockchain, unknown block at height: %d!\n", i);
      return 1;
    }

    if (!delete_block_from_blockchain(block->hash))
    {
      free_block(block);
      return 1;
    }

    // check to see if are rolling back the top block in the blockchain,
    // if so then we need to reset the top block to the previous block of
    // the block we just rolled back.
    if (compare_block_hash(get_current_block_hash(), block->hash))
    {
      block_t *previous_block = get_block_from_hash(block->previous_hash);
      assert(previous_block != NULL);
      set_current_block(previous_block);
      free_block(previous_block);
    }

    free_block(block);
  }

  printf("Successfully rolled back blockchain to height: %d.\n", rollback_height);
  return 0;
}

int valid_median_timestamp(block_t *block)
{
  uint32_t current_block_height = get_block_height();
  if (current_block_height < TIMESTAMP_CHECK_WINDOW)
  {
    return 1;
  }

  block_t *median_block = get_block_from_height(current_block_height - (TIMESTAMP_CHECK_WINDOW / 2));
  assert(median_block != NULL);

  if (block->timestamp <= median_block->timestamp)
  {
    free_block(median_block);
    return 0;
  }

  free_block(median_block);
  return 1;
}

int validate_and_insert_block(block_t *block)
{
  // verify the block, ensure the block is not an orphan or stale,
  // if the block is the genesis, then we do not need to validate it...
  if (!valid_block(block) && get_block_height() > 0)
  {
    return 0;
  }

  // check to see if this block's timestamp is greater than the
  // last median TIMESTAMP_CHECK_WINDOW / 2 block's timestamp...
  if (!valid_median_timestamp(block))
  {
    fprintf(stderr, "Could not insert block into blockchain, block has expired timestamp: %d!\n", block->timestamp);
    return 0;
  }

  // check to ensure that the block header size is less than the
  // maximum allowed block size...
  uint32_t block_header_size = get_block_header_size(block);
  if (block_header_size > MAX_BLOCK_SIZE)
  {
    fprintf(stderr, "Could not insert block into blockchain, block has too big header size: %d!\n", block_header_size);
    return 0;
  }

  // ensure we are not adding a block that already exists in the blockchain...
  if (has_block_by_hash(block->hash))
  {
    return 0;
  }

  // check this blocks previous has against our current top block hash
  if (!compare_block_hash(block->previous_hash, get_current_block_hash()))
  {
    return 0;
  }

  return insert_block(block);
}

/* After we insert block into blockchain
 * Mark unspent txouts as spent for current txins
 * Add current TX w/ unspent txouts to unspent index
 */
int insert_block(block_t *block)
{
  assert(block != NULL);

  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_block_key(key, block->hash);

  buffer_t *buffer = buffer_init();
  serialize_block(buffer, block);
  serialize_transactions_from_block(buffer, block);

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
  buffer_free(buffer);

  for (int i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);

    insert_tx_into_index(key, tx);
    insert_tx_into_unspent_index(tx);

    // ensure that the genesis tx block reward and the block's already_generated_coins
    // value has not been manipulated...
    if (is_generation_tx(tx))
    {
      uint32_t current_block_height = get_block_height();

      block_t *current_block = get_current_block();
      assert(current_block != NULL);

      uint64_t expected_block_reward = get_block_reward(current_block_height, current_block->already_generated_coins);

      // check to ensure that the generation tx reward is valid
      // for it's height in the blockchain...
      output_transaction_t *txout = tx->txouts[0];
      assert(txout != NULL);
      if (txout->amount != expected_block_reward)
      {
        free_block(current_block);
        return 0;
      }

      // check to ensure that the block's already_generated_coins value
      // is equivalent to the previous already_generated_coins plus the block reward...
      uint64_t expected_already_generated_coins = current_block->already_generated_coins + expected_block_reward;
      if (block->already_generated_coins != expected_already_generated_coins)
      {
        free_block(current_block);
        return 0;
      }

      free_block(current_block);
      continue;
    }

    // mark unspent txouts as spent for current txins
    for (int txin_index = 0; txin_index < tx->txin_count; txin_index++)
    {
      input_transaction_t *txin = tx->txins[txin_index];
      unspent_transaction_t *unspent_tx = get_unspent_tx_from_index(txin->transaction);

      assert(txin != NULL);
      assert(unspent_tx != NULL);

      if (((unspent_tx->unspent_txout_count - 1) < txin->txout_index) || unspent_tx->unspent_txouts[txin->txout_index] == NULL)
      {
        free_unspent_transaction(unspent_tx);
        fprintf(stderr, "A txin tried to mark a unspent txout as spent, but it was not found\n");
        continue;
      }
      else
      {
        unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[txin->txout_index];
        assert(unspent_txout != NULL);

        if (unspent_txout->spent == 1)
        {
          free_unspent_transaction(unspent_tx);
          fprintf(stderr, "A txin tried to mark a unspent txout as spent, but it was already spent\n");
          continue;
        }

        unspent_txout->spent = 1;

        int spent_txs = 0;
        for (int j = 0; j < unspent_tx->unspent_txout_count; j++)
        {
          if (unspent_txout->spent == 1)
          {
            spent_txs++;
          }
        }

        if (spent_txs == unspent_tx->unspent_txout_count)
        {
          delete_unspent_tx_from_index(unspent_tx->id);
        }
        else
        {
          insert_unspent_tx_into_index(unspent_tx);
        }

        free_unspent_transaction(unspent_tx);
      }
    }
  }

  if (err != NULL)
  {
    fprintf(stderr, "Could not insert block into blockchain: %s\n", err);

    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
    return 0;
  }

  // update our current top block hash in the blockchain
  set_current_block(block);

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 1;
}

block_t *get_block_from_hash(uint8_t *block_hash)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_block_key(key, block_hash);

  size_t read_len;
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *serialized_block = (uint8_t*)rocksdb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);

  if (err != NULL || serialized_block == NULL)
  {
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    return NULL;
  }

  buffer_t *buffer = buffer_init_data(0, serialized_block, read_len);
  assert(buffer != NULL);

  // deserialize the block
  block_t *block = deserialize_block(buffer);
  assert(block != NULL);

  // deserialize the block's transactions
  deserialize_transactions_to_block(buffer, block);
  buffer_free(buffer);

  rocksdb_free(serialized_block);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  return block;
}

block_t *get_block_from_height(uint32_t height)
{
  uint32_t current_block_height = get_block_height();
  if (height > current_block_height)
  {
    return NULL;
  }

  block_t *block = get_current_block();
  assert(block != NULL);

  if (height == 0)
  {
    return get_block_from_hash(genesis_block.hash);
  }

  for (uint32_t i = current_block_height; i > 0; i--)
  {
    if (i == height)
    {
      break;
    }

    block_t *previous_block = get_block_from_hash(block->previous_hash);
    assert(previous_block != NULL);
    free_block(block);
    block = previous_block;
  }

  return block;
}

int32_t get_block_height_from_hash(uint8_t *block_hash)
{
  uint32_t current_block_height = get_block_height();

  block_t *block = NULL;
  int32_t block_height = -1;

  for (uint32_t i = 0; i <= current_block_height; i++)
  {
    block = get_block_from_height(i);
    assert(block != NULL);
    if (compare_block_hash(block->hash, block_hash))
    {
      block_height = i;
      break;
    }

    free_block(block);
  }

  free_block(block);
  return block_height;
}

int32_t get_block_height_from_block(block_t *block)
{
  return get_block_height_from_hash(block->hash);
}

uint8_t *get_block_hash_from_height(uint32_t height)
{
  block_t *block = get_block_from_height(height);
  if (!block)
  {
    return NULL;
  }

  uint8_t *block_hash = malloc(sizeof(uint8_t) * HASH_SIZE);
  memcpy(block_hash, block->hash, HASH_SIZE);

  free_block(block);
  return block_hash;
}

int has_block_by_hash(uint8_t *block_hash)
{
  block_t *block = get_block_from_hash(block_hash);
  if (!block)
  {
    return 0;
  }

  free_block(block);
  return 1;
}

int has_block_by_height(uint32_t height)
{
  block_t *block = get_block_from_height(height);
  if (!block)
  {
    return 0;
  }

  free_block(block);
  return 1;
}

int insert_tx_into_index(uint8_t *block_key, transaction_t *tx)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_tx_key(key, tx->id);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)block_key, sizeof(key), &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not insert tx into blockchain: %s\n", err);

    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
    return 1;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 0;
}

int insert_tx_into_unspent_index(transaction_t *tx)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_unspent_tx_key(key, tx->id);

  buffer_t *buffer = buffer_init();
  unspent_transaction_t *unspent_tx = transaction_to_unspent_transaction(tx);
  serialize_unspent_transaction(buffer, unspent_tx);
  free_unspent_transaction(unspent_tx);

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
  buffer_free(buffer);

  if (err != NULL)
  {
    fprintf(stderr, "Could not insert tx into blockchain: %s\n", err);

    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
    return 1;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 0;
}

int insert_unspent_tx_into_index(unspent_transaction_t *unspent_tx)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_unspent_tx_key(key, unspent_tx->id);

  buffer_t *buffer = buffer_init();
  serialize_unspent_transaction(buffer, unspent_tx);

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
  buffer_free(buffer);

  if (err != NULL)
  {
    fprintf(stderr, "Could not insert unspent tx into blockchain: %s\n", err);

    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
    return 1;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 0;
}

unspent_transaction_t *get_unspent_tx_from_index(uint8_t *tx_id)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_unspent_tx_key(key, tx_id);

  size_t read_len;
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *serialized_tx = (uint8_t*)rocksdb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);

  if (err != NULL || serialized_tx == NULL)
  {
    rocksdb_free(err);
    rocksdb_free(roptions);
    return NULL;
  }

  unspent_transaction_t *unspent_tx = unspent_transaction_from_serialized(serialized_tx, read_len);
  assert(unspent_tx != NULL);

  rocksdb_free(serialized_tx);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  return unspent_tx;
}

uint8_t *get_block_hash_from_tx_id(uint8_t *tx_id)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_tx_key(key, tx_id);

  size_t read_len;
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *block_key = (uint8_t*)rocksdb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);

  if (err != NULL || block_key == NULL)
  {
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    return NULL;
  }

  uint8_t *block_hash = malloc(sizeof(uint8_t) * HASH_SIZE);
  memcpy(block_hash, block_key + 1, HASH_SIZE);

  rocksdb_free(block_key);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  return block_hash;
}

block_t *get_block_from_tx_id(uint8_t *tx_id)
{
  uint8_t *block_hash = get_block_hash_from_tx_id(tx_id);
  if (block_hash == NULL)
  {
    return NULL;
  }

  block_t *block = get_block_from_hash(block_hash);
  free(block_hash);
  return block;
}

/*
 * This function gets the block height by iterating all keys in the blockchain g_blockchain_db.
 * All blocks get prefixed with "b + <block_hash>".
 *
 * For the sake of dev time, only blocks in the g_blockchain_db are valid + main chain.
 */
uint32_t get_block_height(void)
{
  int32_t block_height = -1;

  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(g_blockchain_db, roptions);

  for (rocksdb_iter_seek(iterator, "b", 1); rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
  {
    size_t key_length;
    uint8_t *key = (uint8_t*)rocksdb_iter_key(iterator, &key_length);
    if (key_length > 0 && key[0] == 'b')
    {
      block_height++;
    }
  }

  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);

  if (block_height < 0)
  {
    return 0;
  }
  else
  {
    return block_height;
  }
}

int delete_block_from_blockchain(uint8_t *block_hash)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_block_key(key, block_hash);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not delete block from blockchain\n");

    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
    return 0;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 1;
}

int delete_tx_from_index(uint8_t *tx_id)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_tx_key(key, tx_id);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not delete tx from index\n");

    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
    return 0;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 1;
}

int delete_unspent_tx_from_index(uint8_t *tx_id)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + 1];
  get_unspent_tx_key(key, tx_id);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not delete tx from unspent index\n");

    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
    return 0;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 1;
}

int set_top_block_hash(uint8_t *block_hash)
{
  char *err = NULL;
  uint8_t key[2];
  get_top_block_key(key);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)block_hash, HASH_SIZE, &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not set blockchain top block hash: %s\n", err);

    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
    return 1;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 0;
}

uint8_t* get_top_block_hash(void)
{
  char *err = NULL;
  uint8_t key[2];
  get_top_block_key(key);

  size_t read_len;
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *block_hash = (uint8_t*)rocksdb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);

  if (err != NULL || block_hash == NULL)
  {
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    return NULL;
  }

  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  return block_hash;
}

int set_top_block(block_t *block)
{
  assert(block != NULL);
  return set_top_block_hash(block->hash);
}

block_t *get_top_block(void)
{
  return get_block_from_hash(get_top_block_hash());
}

int set_current_block_hash(uint8_t *hash)
{
  memcpy(g_blockchain_current_block_hash, hash, HASH_SIZE);
  return 0;
}

uint8_t *get_current_block_hash(void)
{
  return g_blockchain_current_block_hash;
}

int set_current_block(block_t *block)
{
  if (!block)
  {
    return 1;
  }

  set_top_block(block);
  set_current_block_hash(block->hash);
  return 0;
}

block_t *get_current_block(void)
{
  return get_block_from_hash(get_current_block_hash());
}

int get_tx_key(uint8_t *buffer, uint8_t *tx_id)
{
  buffer[0] = 't';
  memcpy(buffer + 1, tx_id, HASH_SIZE);
  return 0;
}

int get_unspent_tx_key(uint8_t *buffer, uint8_t *tx_id)
{
  buffer[0] = 'c';
  memcpy(buffer + 1, tx_id, HASH_SIZE);
  return 0;
}

int get_block_key(uint8_t *buffer, uint8_t *block_hash)
{
  buffer[0] = 'b';
  memcpy(buffer + 1, block_hash, HASH_SIZE);
  return 0;
}

int get_top_block_key(uint8_t *buffer)
{
  memcpy(buffer, "tb", 2);
  return 0;
}

uint64_t get_already_generated_coins(void)
{
  block_t *current_block = get_current_block();
  assert(current_block != NULL);
  uint64_t already_generated_coins = current_block->already_generated_coins;
  free_block(current_block);
  return already_generated_coins;
}

uint64_t get_block_reward(uint32_t block_height, uint64_t already_generated_coins)
{
  uint64_t block_reward = (MAX_MONEY - already_generated_coins) >> BLOCK_REWARD_EMISSION_FACTOR;
  if (already_generated_coins == 0 && GENESIS_REWARD > 0)
  {
    block_reward = GENESIS_REWARD;
  }

  return block_reward;
}

uint64_t get_balance_for_address(uint8_t *address)
{
  uint64_t balance = 0;

  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(g_blockchain_db, roptions);

  for (rocksdb_iter_seek(iterator, "c", 1); rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
  {
    size_t key_length;
    char *key = (char*)rocksdb_iter_key(iterator, &key_length);
    if (key_length > 0 && key[0] == 'c')
    {
      size_t value_length;
      uint8_t *value = (uint8_t*)rocksdb_iter_value(iterator, &value_length);
      unspent_transaction_t *tx = unspent_transaction_from_serialized(value, value_length);
      for (int i = 0; i < tx->unspent_txout_count; i++)
      {
        unspent_output_transaction_t *unspent_txout = tx->unspent_txouts[i];
        if (!compare_addresses(unspent_txout->address, address))
        {
          continue;
        }

        if (unspent_txout->spent == 0)
        {
          balance += unspent_txout->amount;
        }
      }
    }
  }

  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);
  return balance;
}
