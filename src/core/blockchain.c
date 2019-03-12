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

#include "common/logger.h"
#include "common/tinycthread.h"
#include "common/util.h"
#include "common/vec.h"

#include "block.h"
#include "blockchain.h"
#include "difficulty.h"

#include "wallet/wallet.h"

static mtx_t g_blockchain_lock;

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

static vec_int_t g_timestamps;
static vec_int_t g_cumulative_difficulties;

static size_t g_num_timestamps = 0;
static size_t g_num_cumulative_difficulties = 0;

static uint32_t g_timestamps_and_difficulties_height = 0;

static uint8_t g_difficulty_for_next_block_top_hash[HASH_SIZE] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

static uint32_t g_difficulty_for_next_block = 1;

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

  mtx_init(&g_blockchain_lock, mtx_plain);
  g_blockchain_dir = blockchain_dir;

  vec_init(&g_timestamps);
  vec_init(&g_cumulative_difficulties);

  char *err = NULL;
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(options, 1);

  g_blockchain_db = rocksdb_open(options, blockchain_dir, &err);

  if (err != NULL)
  {
    LOG_ERROR("Could not open blockchain database: %s!", err);

    rocksdb_free(err);
    rocksdb_free(options);
    return 1;
  }

  if (!has_block_by_hash(genesis_block.hash))
  {
    if (!validate_and_insert_block(&genesis_block))
    {
      LOG_ERROR("Could not insert genesis block into blockchain!");

      rocksdb_free(err);
      rocksdb_free(options);
      return 1;
    }
  }
  else
  {
    block_t *top_block = get_top_block();
    if (top_block == NULL)
    {
      LOG_ERROR("Could not get unknown blockchain top block!");

      rocksdb_free(err);
      rocksdb_free(options);
      return 1;
    }

    set_current_block(top_block);
    free_block(top_block);
  }

  LOG_INFO("Successfully initialized blockchain.");
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
  mtx_destroy(&g_blockchain_lock);
  g_blockchain_is_open = 0;

  vec_deinit(&g_timestamps);
  vec_deinit(&g_cumulative_difficulties);

  g_num_timestamps = 0;
  g_num_cumulative_difficulties = 0;
  g_timestamps_and_difficulties_height = 0;

  g_difficulty_for_next_block = 0;

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
    LOG_ERROR("Could not open backup blockchain database: %s!", err);

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
    LOG_ERROR("Could not backup blockchain database: %s!", err);

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
    LOG_ERROR("Could not restore blockchain database from backup: %s!", err);

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
    LOG_WARNING("Could not rollback blockchain to height: %d, current blockchain top block height is: %d!", rollback_height, current_block_height);
    return 1;
  }

  for (uint32_t i = current_block_height; i > 0; i--)
  {
    if (i == rollback_height)
    {
      break;
    }

    block_t *block = get_block_from_height(i);
    if (block == NULL)
    {
      LOG_WARNING("Could not reset blockchain, unknown block at height: %d!", i);
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

  LOG_INFO("Successfully rolled back blockchain to height: %d!", rollback_height);
  return 0;
}

uint64_t get_cumulative_emission(void)
{
  block_t *current_block = get_current_block();
  assert(current_block != NULL);
  uint64_t cumulative_emission = current_block->cumulative_emission;
  free_block(current_block);
  return cumulative_emission;
}

uint64_t get_block_reward(uint32_t block_height, uint64_t cumulative_emission)
{
  uint64_t block_reward = (MAX_MONEY - cumulative_emission) >> BLOCK_REWARD_EMISSION_FACTOR;
  if (cumulative_emission == 0 && GENESIS_REWARD > 0)
  {
    block_reward = GENESIS_REWARD;
  }

  return block_reward;
}

uint64_t get_block_cumulative_difficulty(uint32_t block_height)
{
  block_t *block = get_block_from_height(block_height);
  assert(block != NULL);
  uint64_t cumulative_difficulty = block->cumulative_difficulty;
  free_block(block);
  return cumulative_difficulty;
}

uint64_t get_block_difficulty(uint32_t block_height)
{
  difficulty_info_t difficulty_info;
  uint32_t height = block_height;
  height++;

  vec_init(&difficulty_info.timestamps);
  vec_init(&difficulty_info.cumulative_difficulties);

  mtx_lock(&g_blockchain_lock);
  if (g_timestamps_and_difficulties_height != 0 && ((height - g_timestamps_and_difficulties_height) == 1) && g_num_timestamps >= DIFFICULTY_BLOCKS_COUNT)
  {
    uint32_t index = height - 1;
    block_t *block = get_block_from_height(index);
    assert(block != NULL);

    assert(vec_push(&g_timestamps, block->timestamp) == 0);
    assert(vec_push(&g_cumulative_difficulties, block->cumulative_difficulty) == 0);

    free_block(block);

    g_num_timestamps++;
    g_num_cumulative_difficulties++;

    while (g_num_timestamps > DIFFICULTY_BLOCKS_COUNT)
    {
      vec_splice(&g_timestamps, 0, 1);
      g_num_timestamps--;
    }

    while (g_num_cumulative_difficulties > DIFFICULTY_BLOCKS_COUNT)
    {
      vec_splice(&g_cumulative_difficulties, 0, 1);
      g_num_cumulative_difficulties--;
    }

    vec_extend(&difficulty_info.timestamps, &g_timestamps);
    vec_extend(&difficulty_info.cumulative_difficulties, &g_cumulative_difficulties);

    g_timestamps_and_difficulties_height = height;
  }
  else
  {
    uint32_t offset = height - (uint32_t)(MIN(height, (uint32_t)DIFFICULTY_BLOCKS_COUNT));
    if (offset == 0)
    {
      offset++;
    }

    if (height > offset)
    {
      assert(vec_reserve(&difficulty_info.timestamps, height - offset) == 0);
      assert(vec_reserve(&difficulty_info.cumulative_difficulties, height - offset) == 0);
    }

    g_num_timestamps = 0;
    g_num_cumulative_difficulties = 0;

    for (; offset < height; offset++)
    {
      block_t *block = get_block_from_height(offset);
      assert(block != NULL);

      assert(vec_push(&difficulty_info.timestamps, block->timestamp) == 0);
      assert(vec_push(&difficulty_info.cumulative_difficulties, block->cumulative_difficulty) == 0);

      free_block(block);

      g_num_timestamps++;
      g_num_cumulative_difficulties++;
    }

    vec_clear(&g_timestamps);
    vec_clear(&g_cumulative_difficulties);

    vec_extend(&g_timestamps, &difficulty_info.timestamps);
    vec_extend(&g_cumulative_difficulties, &difficulty_info.cumulative_difficulties);

    g_timestamps_and_difficulties_height = height;
  }

  vec_truncate(&difficulty_info.timestamps, DIFFICULTY_WINDOW);
  vec_truncate(&difficulty_info.cumulative_difficulties, DIFFICULTY_WINDOW);

  difficulty_info.num_timestamps = MIN(g_num_timestamps, DIFFICULTY_WINDOW);
  difficulty_info.num_cumulative_difficulties = MIN(g_num_cumulative_difficulties, DIFFICULTY_WINDOW);
  difficulty_info.target_seconds = DIFFICULTY_TARGET;

  uint64_t difficulty = get_next_difficulty(difficulty_info);

  vec_deinit(&difficulty_info.timestamps);
  vec_deinit(&difficulty_info.cumulative_difficulties);

  mtx_unlock(&g_blockchain_lock);
  return difficulty;
}

uint64_t get_next_block_difficulty(void)
{
  uint32_t current_block_height = get_block_height();
  uint8_t *current_block_hash = get_current_block_hash();

  if (compare_block_hash(current_block_hash, (uint8_t*)&g_difficulty_for_next_block_top_hash))
  {
    return g_difficulty_for_next_block;
  }

  uint64_t difficulty = get_block_difficulty(current_block_height);

  memcpy(g_difficulty_for_next_block_top_hash, current_block_hash, HASH_SIZE);
  g_difficulty_for_next_block = difficulty;

  return difficulty;
}

int valid_block_median_timestamp(block_t *block)
{
  assert(block != NULL);
  uint32_t current_block_height = get_block_height();
  if (current_block_height < TIMESTAMP_CHECK_WINDOW)
  {
    return 1;
  }

  block_t *median_block = get_block_from_height(current_block_height - (TIMESTAMP_CHECK_WINDOW / 2));
  assert(median_block != NULL);

  uint32_t median_timestamp = median_block->timestamp;
  free_block(median_block);

  return block->timestamp > median_timestamp;
}

int valid_block_generation_transaction(block_t *block, uint32_t block_height)
{
  assert(block != NULL);

  // if the genesis block has no transactions, there's no need to
  // check it; but if it does indeed have transactions
  // then we can check it as we would normally...
  if (block_height == 0 && block->transaction_count == 0)
  {
    return 1;
  }

  transaction_t *tx = block->transactions[0];
  assert(tx != NULL);

  output_transaction_t *txout = tx->txouts[0];
  assert(txout != NULL);

  uint64_t expected_block_reward = 0;
  uint64_t expected_cumulative_emission = 0;

  if (block_height > 0)
  {
    block_t *previous_block = get_block_from_hash(block->previous_hash);
    assert(previous_block != NULL);

    int32_t previous_height = get_block_height_from_block(previous_block);
    assert(previous_height >= 0);

    expected_block_reward = get_block_reward(previous_height, previous_block->cumulative_emission);
    expected_cumulative_emission = previous_block->cumulative_emission + expected_block_reward;
    free_block(previous_block);
  }
  else
  {
    expected_block_reward = get_block_reward(0, 0);
    expected_cumulative_emission = expected_block_reward;
  }

  return (txout->amount == expected_block_reward && block->cumulative_emission == expected_cumulative_emission);
}

int validate_and_insert_block(block_t *block)
{
  uint32_t current_block_height = get_block_height();

  // verify the block, ensure the block is not an orphan or stale,
  // if the block is the genesis, then we do not need to validate it...
  if (!valid_block(block) && current_block_height > 0)
  {
    return 0;
  }

  // check to see if this block's timestamp is greater than the
  // last median TIMESTAMP_CHECK_WINDOW / 2 block's timestamp...
  if (!valid_block_median_timestamp(block))
  {
    LOG_DEBUG("Could not insert block into blockchain, block has expired timestamp: %d!", block->timestamp);
    return 0;
  }

  // validate the block's generation transaction
  if (!valid_block_generation_transaction(block, current_block_height))
  {
    LOG_DEBUG("Could not insert block into blockchain, block has invalid generation transaction!");
    return 0;
  }

  // check the block's difficulty value, also check the block's
  // hash to see if it's difficulty is valid.
  if (current_block_height > 0)
  {
    uint64_t expected_cumulative_difficulty = get_block_cumulative_difficulty(current_block_height) + block->difficulty;
    if (block->cumulative_difficulty != expected_cumulative_difficulty)
    {
      LOG_DEBUG("Could not insert block into blockchain, block has invalid cumulative difficulty: %llu expected: %llu!", block->cumulative_difficulty, expected_cumulative_difficulty);
      return 0;
    }

    uint64_t expected_difficulty = get_next_block_difficulty();
    if (block->difficulty != expected_difficulty)
    {
      LOG_DEBUG("Could not insert block into blockchain, block has invalid difficulty: %llu expected: %llu!", block->difficulty, expected_difficulty);
      return 0;
    }

    if (!check_hash(block->hash, expected_difficulty))
    {
      LOG_ERROR("Could not insert block into blockchain, block does not have enough PoW: %llu expected: %llu!", block->difficulty, expected_difficulty);
      return 0;
    }
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

  mtx_lock(&g_blockchain_lock);
  int result = insert_block(block);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

/* After we insert block into blockchain
 * Mark unspent txouts as spent for current txins
 * Add current TX w/ unspent txouts to unspent index
 */
int insert_block(block_t *block)
{
  assert(block != NULL);

  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_BLOCK];
  get_block_key(key, block->hash);

  buffer_t *buffer = buffer_init();
  serialize_block(buffer, block);
  serialize_transactions_from_block(buffer, block);

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
  buffer_free(buffer);

  for (uint32_t i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);

    insert_tx_into_index(key, tx);
    insert_tx_into_unspent_index(tx);

    if (is_generation_tx(tx))
    {
      continue;
    }

    // mark unspent txouts as spent for current txins
    for (uint32_t txin_index = 0; txin_index < tx->txin_count; txin_index++)
    {
      input_transaction_t *txin = tx->txins[txin_index];
      unspent_transaction_t *unspent_tx = get_unspent_tx_from_index(txin->transaction);

      assert(txin != NULL);
      assert(unspent_tx != NULL);

      if (((unspent_tx->unspent_txout_count - 1) < txin->txout_index) || unspent_tx->unspent_txouts[txin->txout_index] == NULL)
      {
        free_unspent_transaction(unspent_tx);
        LOG_DEBUG("A txin tried to mark a unspent txout as spent, but it was not found!");
        continue;
      }
      else
      {
        unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[txin->txout_index];
        assert(unspent_txout != NULL);

        if (unspent_txout->spent == 1)
        {
          free_unspent_transaction(unspent_tx);
          LOG_DEBUG("A txin tried to mark a unspent txout as spent, but it was already spent!");
          continue;
        }

        unspent_txout->spent = 1;

        uint32_t spent_txs = 0;
        for (uint32_t j = 0; j < unspent_tx->unspent_txout_count; j++)
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
    LOG_ERROR("Could not insert block into blockchain storage: %s!", err);

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
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_BLOCK];
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
  assert(block != NULL);
  return get_block_height_from_hash(block->hash);
}

uint8_t *get_block_hash_from_height(uint32_t height)
{
  block_t *block = get_block_from_height(height);
  if (block == NULL)
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
  if (block == NULL)
  {
    return 0;
  }

  free_block(block);
  return 1;
}

int has_block_by_height(uint32_t height)
{
  block_t *block = get_block_from_height(height);
  if (block == NULL)
  {
    return 0;
  }

  free_block(block);
  return 1;
}

int insert_tx_into_index(uint8_t *block_key, transaction_t *tx)
{
  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_TX];
  get_tx_key(key, tx->id);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)block_key, sizeof(key), &err);

  if (err != NULL)
  {
    LOG_ERROR("Could not insert tx into blockchain: %s!", err);

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
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_UNSPENT_TX];
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
    LOG_ERROR("Could not insert tx into blockchain: %s!", err);

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
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_UNSPENT_TX];
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
    LOG_ERROR("Could not insert unspent tx into blockchain: %s!", err);

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
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_UNSPENT_TX];
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
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_TX];
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

  for (rocksdb_iter_seek(iterator, DB_KEY_PREFIX_BLOCK, DB_KEY_PREFIX_SIZE_BLOCK);
    rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
  {
    size_t key_length;
    uint8_t *key = (uint8_t*)rocksdb_iter_key(iterator, &key_length);
    if (key_length > 0 && key[0] == (char)*DB_KEY_PREFIX_BLOCK)
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
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_BLOCK];
  get_block_key(key, block_hash);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);

  if (err != NULL)
  {
    LOG_ERROR("Could not delete block: %s from blockchain storage!", hash_to_str(block_hash));

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
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_TX];
  get_tx_key(key, tx_id);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);

  if (err != NULL)
  {
    LOG_ERROR("Could not delete tx: %s from index!", hash_to_str(tx_id));

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
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_UNSPENT_TX];
  get_unspent_tx_key(key, tx_id);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);

  if (err != NULL)
  {
    LOG_ERROR("Could not delete tx: %s from unspent index!", hash_to_str(tx_id));

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
  uint8_t key[DB_KEY_PREFIX_SIZE_TOP_BLOCK];
  get_top_block_key(key);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)block_hash, HASH_SIZE, &err);

  if (err != NULL)
  {
    LOG_ERROR("Could not set blockchain storage top block hash: %s!", err);

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
  uint8_t key[DB_KEY_PREFIX_SIZE_TOP_BLOCK];
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
  if (block == NULL)
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

uint32_t get_blocks_since_hash(uint8_t *block_hash)
{
  block_t *block = get_block_from_hash(block_hash);
  assert(block != NULL);

  int32_t block_height = get_block_height_from_hash(block_hash);
  assert(block_height >= 0);
  free_block(block);

  uint32_t current_block_height = get_block_height();
  if (current_block_height > block_height)
  {
    return current_block_height - block_height;
  }
  else
  {
    return 0;
  }
}

uint32_t get_blocks_since_block(block_t *block)
{
  assert(block != NULL);
  return get_blocks_since_hash(block->hash);
}

int get_tx_key(uint8_t *buffer, uint8_t *tx_id)
{
  memcpy(buffer, DB_KEY_PREFIX_TX, DB_KEY_PREFIX_SIZE_TX);
  memcpy(buffer + DB_KEY_PREFIX_SIZE_TX, tx_id, HASH_SIZE);
  return 0;
}

int get_unspent_tx_key(uint8_t *buffer, uint8_t *tx_id)
{
  memcpy(buffer, DB_KEY_PREFIX_UNSPENT_TX, DB_KEY_PREFIX_SIZE_UNSPENT_TX);
  memcpy(buffer + DB_KEY_PREFIX_SIZE_UNSPENT_TX, tx_id, HASH_SIZE);
  return 0;
}

int get_block_key(uint8_t *buffer, uint8_t *block_hash)
{
  memcpy(buffer, DB_KEY_PREFIX_BLOCK, DB_KEY_PREFIX_SIZE_BLOCK);
  memcpy(buffer + DB_KEY_PREFIX_SIZE_BLOCK, block_hash, HASH_SIZE);
  return 0;
}

int get_top_block_key(uint8_t *buffer)
{
  memcpy(buffer, DB_KEY_PREFIX_TOP_BLOCK, DB_KEY_PREFIX_SIZE_TOP_BLOCK);
  return 0;
}

uint64_t get_balance_for_address(uint8_t *address)
{
  uint64_t balance = 0;

  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(g_blockchain_db, roptions);

  mtx_lock(&g_blockchain_lock);
  for (rocksdb_iter_seek(iterator, DB_KEY_PREFIX_UNSPENT_TX, DB_KEY_PREFIX_SIZE_UNSPENT_TX);
    rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
  {
    size_t key_length;
    char *key = (char*)rocksdb_iter_key(iterator, &key_length);
    if (key_length > 0 && key[0] == (char)*DB_KEY_PREFIX_UNSPENT_TX)
    {
      size_t value_length;
      uint8_t *value = (uint8_t*)rocksdb_iter_value(iterator, &value_length);
      unspent_transaction_t *tx = unspent_transaction_from_serialized(value, value_length);
      assert(tx != NULL);

      for (uint32_t i = 0; i < tx->unspent_txout_count; i++)
      {
        unspent_output_transaction_t *unspent_txout = tx->unspent_txouts[i];
        assert(unspent_txout != NULL);

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

  mtx_unlock(&g_blockchain_lock);

  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);

  return balance;
}
