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
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

#include <openssl/bn.h>

#ifdef USE_LEVELDB
#include <leveldb/c.h>
#else
#include <rocksdb/c.h>
#endif

#include "common/buffer_iterator.h"
#include "common/buffer.h"
#include "common/logger.h"
#include "common/tinycthread.h"
#include "common/util.h"
#include "common/vec.h"

#include "block.h"
#include "blockchain.h"
#include "mempool.h"
#include "pow.h"

#include "crypto/bignum_util.h"
#include "crypto/cryptoutil.h"

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

static int g_blockchain_want_compression = 1;

static int g_blockchain_is_open = 0;
static int g_blockchain_backup_is_open = 0;

#ifdef USE_LEVELDB
static int g_blockchain_compression_type = leveldb_snappy_compression;
static leveldb_t *g_blockchain_db = NULL;
static leveldb_t *g_blockchain_backup_db = NULL;
#else
static int g_blockchain_compression_type = rocksdb_lz4_compression;
static rocksdb_t *g_blockchain_db = NULL;
static rocksdb_backup_engine_t *g_blockchain_backup_db = NULL;
#endif

int valid_compression_type(int compression_type)
{
  switch (compression_type)
  {
  #ifdef USE_LEVELDB
    case leveldb_snappy_compression:
      return 1;
    case leveldb_no_compression:
    default:
      return 0;
  #else
    case rocksdb_snappy_compression:
    case rocksdb_zlib_compression:
    case rocksdb_bz2_compression:
    case rocksdb_lz4_compression:
    case rocksdb_lz4hc_compression:
    case rocksdb_xpress_compression:
    case rocksdb_zstd_compression:
      return 1;
    case rocksdb_no_compression:
    default:
      return 0;
  #endif
  }
}

const char* get_compression_type_str(int compression_type)
{
  switch (compression_type)
  {
  #ifdef USE_LEVELDB
    case leveldb_snappy_compression:
      return "snappy";
    case leveldb_no_compression:
    default:
      return "unknown";
  #else
    case rocksdb_snappy_compression:
      return "snappy";
    case rocksdb_zlib_compression:
      return "zlib";
    case rocksdb_bz2_compression:
      return "bz2";
    case rocksdb_lz4_compression:
      return "lz4";
    case rocksdb_lz4hc_compression:
      return "lz4hc";
    case rocksdb_xpress_compression:
      return "xpress";
    case rocksdb_zstd_compression:
      return "zstandard";
    case rocksdb_no_compression:
    default:
      return "unknown";
  #endif
  }
}

int get_compression_type_from_str(const char *compression_type_str)
{
#ifdef USE_LEVELDB
  if (string_equals(compression_type_str, "snappy"))
  {
    return leveldb_snappy_compression;
  }

  return leveldb_no_compression;
#else
  if (string_equals(compression_type_str, "snappy"))
  {
    return rocksdb_snappy_compression;
  }
  else if (string_equals(compression_type_str, "zlib"))
  {
    return rocksdb_zlib_compression;
  }
  else if (string_equals(compression_type_str, "bz2"))
  {
    return rocksdb_bz2_compression;
  }
  else if (string_equals(compression_type_str, "lz4"))
  {
    return rocksdb_lz4_compression;
  }
  else if (string_equals(compression_type_str, "lz4hc"))
  {
    return rocksdb_lz4hc_compression;
  }
  else if (string_equals(compression_type_str, "xpress"))
  {
    return rocksdb_xpress_compression;
  }
  else if (string_equals(compression_type_str, "zstandard"))
  {
    return rocksdb_zstd_compression;
  }

  return rocksdb_no_compression;
#endif
}

void set_want_blockchain_compression(int want_blockchain_compression)
{
  g_blockchain_want_compression = want_blockchain_compression;
}

int get_want_blockchain_compression(void)
{
  return g_blockchain_want_compression;
}

void set_blockchain_compression_type(int compression_type)
{
  assert(valid_compression_type(compression_type) == 1);
  g_blockchain_compression_type = compression_type;
}

int get_blockchain_compression_type(void)
{
  return g_blockchain_compression_type;
}

const char* get_blockchain_dir(void)
{
  return g_blockchain_dir;
}

const char* get_blockchain_backup_dir(const char *blockchain_dir)
{
  return string_copy(blockchain_dir, g_blockchain_backup_dir);
}

int repair_blockchain(const char *blockchain_dir)
{
  if (g_blockchain_is_open)
  {
    LOG_ERROR("Cannot repair blockchain database: %s, blockchain is currently open!", blockchain_dir);
    return 1;
  }

  char *err = NULL;
#ifdef USE_LEVELDB
  leveldb_options_t *options = leveldb_options_create();
  leveldb_options_set_create_if_missing(options, 1);
#else
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(options, 1);
#endif

#ifdef USE_LEVELDB
  leveldb_repair_db(options, blockchain_dir, &err);
#else
  rocksdb_repair_db(options, blockchain_dir, &err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Could not repair blockchain database: %s, error occurred: %s!", blockchain_dir, err);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_free(options);
  #else
    rocksdb_free(err);
    rocksdb_options_destroy(options);
  #endif
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_free(options);
#else
  rocksdb_free(err);
  rocksdb_options_destroy(options);
#endif

  LOG_INFO("Successfully repaired blockchain database: %s!", blockchain_dir);
  return 0;
}

int open_blockchain(const char *blockchain_dir)
{
  if (g_blockchain_is_open)
  {
    return 0;
  }

  mtx_init(&g_blockchain_lock, mtx_recursive);
  g_blockchain_dir = blockchain_dir;

  char *err = NULL;
#ifdef USE_LEVELDB
  leveldb_options_t *options = leveldb_options_create();
  leveldb_options_set_create_if_missing(options, 1);
#else
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(options, 1);
#endif

#ifdef USE_LEVELDB
  g_blockchain_db = leveldb_open(options, blockchain_dir, &err);
#else
  g_blockchain_db = rocksdb_open(options, blockchain_dir, &err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Could not open blockchain database: %s!", err);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_free(options);
  #else
    rocksdb_free(err);
    rocksdb_options_destroy(options);
  #endif
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_free(options);
#else
  rocksdb_free(err);
  rocksdb_options_destroy(options);
#endif

  block_t *genesis_block = get_genesis_block();
  assert(genesis_block != NULL);

  if (has_block_by_hash(genesis_block->hash) == 0)
  {
    if (validate_and_insert_block(genesis_block))
    {
      char *genesis_block_hash = bin2hex(genesis_block->hash, HASH_SIZE);
      LOG_ERROR("Could not insert genesis block into blockchain: %s", genesis_block_hash);
      free(genesis_block_hash);
      return 1;
    }
  }
  else
  {
    block_t *top_block = get_top_block();
    if (top_block == NULL)
    {
      LOG_ERROR("Could not get unknown blockchain top block!");
      return 1;
    }

    set_current_block(top_block);
    free_block(top_block);
  }

  LOG_INFO("Successfully initialized blockchain.");
  g_blockchain_is_open = 1;
  return 0;
}

int remove_blockchain(const char *blockchain_dir)
{
  char *err = NULL;
#ifdef USE_LEVELDB
  leveldb_options_t *options = leveldb_options_create();
  leveldb_destroy_db(options, blockchain_dir, &err);
#else
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_destroy_db(options, blockchain_dir, &err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Failed to remove blockchain database: %s!", err);
    goto remove_db_fail;
  }

  const char *blockchain_backup_dir = get_blockchain_backup_dir(blockchain_dir);
#ifdef USE_LEVELDB
  leveldb_destroy_db(options, blockchain_backup_dir, &err);
#else
  rocksdb_destroy_db(options, blockchain_backup_dir, &err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Failed to remove blockchain backup database: %s!", err);
    goto remove_db_fail;
  }

#ifdef USE_LEVELDB
  leveldb_options_destroy(options);
#else
  rocksdb_options_destroy(options);
#endif
  return 0;

remove_db_fail:
#ifdef USE_LEVELDB
  leveldb_options_destroy(options);
#else
  rocksdb_options_destroy(options);
#endif
  return 1;
}

int close_blockchain(void)
{
  if (g_blockchain_is_open == 0)
  {
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_close(g_blockchain_db);
#else
  rocksdb_close(g_blockchain_db);
#endif

  mtx_destroy(&g_blockchain_lock);
  if (close_backup_blockchain())
  {
    return 1;
  }

  g_blockchain_is_open = 0;
  return 0;
}

int open_backup_blockchain(void)
{
  if (g_blockchain_backup_is_open)
  {
    return 1;
  }

  char *err = NULL;
#ifdef USE_LEVELDB
  leveldb_options_t *options = leveldb_options_create();
  leveldb_options_set_create_if_missing(options, 1);
#else
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(options, 1);
#endif

  if (g_blockchain_want_compression)
  {
  #ifdef USE_LEVELDB
    leveldb_options_set_compression(options, g_blockchain_compression_type);
  #else
    rocksdb_options_set_compression(options, g_blockchain_compression_type);
  #endif

    LOG_INFO("Blockchain storage compression is enabled, using the `%s` compression algorithm!",
      get_compression_type_str(g_blockchain_compression_type));
  }
  else
  {
    LOG_INFO("Blockchain storage compression is disabled!");
  }

  const char *blockchain_backup_dir = get_blockchain_backup_dir(g_blockchain_dir);
#ifdef USE_LEVELDB
  g_blockchain_backup_db = leveldb_open(options, blockchain_backup_dir, &err);
#else
  g_blockchain_backup_db = rocksdb_backup_engine_open(options, blockchain_backup_dir, &err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Could not open backup blockchain database: %s!", err);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_free(options);
  #else
    rocksdb_free(err);
    rocksdb_options_destroy(options);
  #endif
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_free(options);
#else
  rocksdb_free(err);
  rocksdb_options_destroy(options);
#endif

  g_blockchain_backup_is_open = 1;
  return 0;
}

int close_backup_blockchain(void)
{
  if (g_blockchain_backup_is_open == 0)
  {
    return 1;
  }

  #ifdef USE_LEVELDB
    leveldb_close(g_blockchain_backup_db);
  #else
    rocksdb_backup_engine_close(g_blockchain_backup_db);
  #endif

  g_blockchain_backup_is_open = 0;
  return 0;
}

int init_blockchain(const char *blockchain_dir)
{
  if (open_blockchain(blockchain_dir))
  {
    return 1;
  }

  if (open_backup_blockchain())
  {
    return 1;
  }

  return 0;
}

#ifdef USE_LEVELDB
int purge_all_entries_from_database(leveldb_t *db)
#else
int purge_all_entries_from_database(rocksdb_t *db)
#endif
{
  assert(db != NULL);

  char *err = NULL;
#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  leveldb_iterator_t *iterator = leveldb_create_iterator(db, roptions);
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_writebatch_t *write_batch = leveldb_writebatch_create();
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(db, roptions);
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_writebatch_t *write_batch = rocksdb_writebatch_create();
#endif

#ifdef USE_LEVELDB
  for (leveldb_iter_seek_to_first(iterator);
    leveldb_iter_valid(iterator); leveldb_iter_next(iterator))
#else
  for (rocksdb_iter_seek_to_first(iterator);
    rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
#endif
  {
    size_t key_length;
  #ifdef USE_LEVELDB
    uint8_t *key = (uint8_t*)leveldb_iter_key(iterator, &key_length);
    assert(key != NULL);

    leveldb_writebatch_delete(write_batch, (char*)key, key_length);
  #else
    uint8_t *key = (uint8_t*)rocksdb_iter_key(iterator, &key_length);
    assert(key != NULL);

    rocksdb_writebatch_delete(write_batch, (char*)key, key_length);
  #endif
  }

#ifdef USE_LEVELDB
  leveldb_write(db, woptions, write_batch, &err);
#else
  rocksdb_write(db, woptions, write_batch, &err);
#endif
  if (err != NULL)
  {
    LOG_ERROR("Failed to purge all entries from database!");

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_readoptions_destroy(roptions);
    leveldb_iter_destroy(iterator);
    leveldb_writeoptions_destroy(woptions);
    leveldb_writebatch_clear(write_batch);
    leveldb_writebatch_destroy(write_batch);
  #else
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    rocksdb_iter_destroy(iterator);
    rocksdb_writeoptions_destroy(woptions);
    rocksdb_writebatch_clear(write_batch);
    rocksdb_writebatch_destroy(write_batch);
  #endif
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
  leveldb_iter_destroy(iterator);
  leveldb_writeoptions_destroy(woptions);
  leveldb_writebatch_clear(write_batch);
  leveldb_writebatch_destroy(write_batch);
#else
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);
  rocksdb_writeoptions_destroy(woptions);
  rocksdb_writebatch_clear(write_batch);
  rocksdb_writebatch_destroy(write_batch);
#endif
  return 0;
}

#ifdef USE_LEVELDB
int copy_all_entries_to_database(leveldb_t *from_db, leveldb_t *to_db)
#else
int copy_all_entries_to_database(rocksdb_t *from_db, rocksdb_t *to_db)
#endif
{
  assert(from_db != NULL);
  assert(to_db != NULL);

  char *err = NULL;
#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  leveldb_iterator_t *iterator = leveldb_create_iterator(from_db, roptions);
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_writebatch_t *write_batch = leveldb_writebatch_create();
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(from_db, roptions);
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_writebatch_t *write_batch = rocksdb_writebatch_create();
#endif

#ifdef USE_LEVELDB
  for (leveldb_iter_seek_to_first(iterator);
    leveldb_iter_valid(iterator); leveldb_iter_next(iterator))
#else
  for (rocksdb_iter_seek_to_first(iterator);
    rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
#endif
  {
    size_t key_length;
  #ifdef USE_LEVELDB
    uint8_t *key = (uint8_t*)leveldb_iter_key(iterator, &key_length);
    assert(key != NULL);
  #else
    uint8_t *key = (uint8_t*)rocksdb_iter_key(iterator, &key_length);
    assert(key != NULL);
  #endif

    size_t read_len;
  #ifdef USE_LEVELDB
    uint8_t *value = (uint8_t*)leveldb_get(from_db, roptions, (char*)key, key_length, &read_len, &err);
  #else
    uint8_t *value = (uint8_t*)rocksdb_get(from_db, roptions, (char*)key, key_length, &read_len, &err);
  #endif
    if (err != NULL || value == NULL)
    {
      LOG_ERROR("Failed to retrieve value from key: %s in database!", key);

    #ifdef USE_LEVELDB
      leveldb_free(key);
      leveldb_free(value);
    #else
      rocksdb_free(key);
      rocksdb_free(value);
    #endif
      goto copy_entries_fail;
    }

  #ifdef USE_LEVELDB
    leveldb_writebatch_put(write_batch, (char*)key, key_length, (char*)value, read_len);
  #else
    rocksdb_writebatch_put(write_batch, (char*)key, key_length, (char*)value, read_len);
  #endif
  }

#ifdef USE_LEVELDB
  leveldb_write(to_db, woptions, write_batch, &err);
#else
  rocksdb_write(to_db, woptions, write_batch, &err);
#endif
  if (err != NULL)
  {
    LOG_ERROR("Failed to copy entries to database!");
    goto copy_entries_fail;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
  leveldb_iter_destroy(iterator);
  leveldb_writeoptions_destroy(woptions);
  leveldb_writebatch_clear(write_batch);
  leveldb_writebatch_destroy(write_batch);
#else
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);
  rocksdb_writeoptions_destroy(woptions);
  rocksdb_writebatch_clear(write_batch);
  rocksdb_writebatch_destroy(write_batch);
#endif
  return 0;

copy_entries_fail:
#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
  leveldb_iter_destroy(iterator);
  leveldb_writeoptions_destroy(woptions);
  leveldb_writebatch_clear(write_batch);
  leveldb_writebatch_destroy(write_batch);
#else
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);
  rocksdb_writeoptions_destroy(woptions);
  rocksdb_writebatch_clear(write_batch);
  rocksdb_writebatch_destroy(write_batch);
#endif
  return 1;
}

int backup_blockchain_nolock(void)
{
  if (g_blockchain_backup_is_open == 0)
  {
    return 1;
  }

#ifdef USE_LEVELDB
  if (purge_all_entries_from_database(g_blockchain_backup_db))
  {
    LOG_ERROR("Could not backup blockchain database, failed to purge old backups!");
    return 1;
  }

  if (copy_all_entries_to_database(g_blockchain_db, g_blockchain_backup_db))
  {
    LOG_ERROR("Could not backup blockchain database, failed to copy entries to backup database!");
    return 1;
  }
#else
  char *err = NULL;
  rocksdb_backup_engine_purge_old_backups(g_blockchain_backup_db, 0, &err);
  if (err != NULL)
  {
    LOG_ERROR("Could not backup blockchain database, failed to purge old backups: %s!", err);
    rocksdb_free(err);
    return 1;
  }

  rocksdb_backup_engine_create_new_backup(g_blockchain_backup_db, g_blockchain_db, &err);
  if (err != NULL)
  {
    LOG_ERROR("Could not backup blockchain database, failed to create new backup: %s!", err);
    rocksdb_free(err);
    return 1;
  }

  rocksdb_free(err);
#endif

  LOG_INFO("Successfully backed up blockchain database!");
  return 0;
}

int backup_blockchain(void)
{
  mtx_lock(&g_blockchain_lock);
  int result = backup_blockchain_nolock();
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int restore_blockchain_nolock(void)
{
  if (g_blockchain_backup_is_open == 0)
  {
    return 1;
  }

#ifdef USE_LEVELDB
  if (purge_all_entries_from_database(g_blockchain_db))
  {
    LOG_ERROR("Could not restore blockchain database from backup, failed to purge blockchain database!");
    return 1;
  }

  if (copy_all_entries_to_database(g_blockchain_backup_db, g_blockchain_db))
  {
    LOG_ERROR("Could not backup blockchain database, failed to copy entires from backup database!");
    return 1;
  }
#else
  char *err = NULL;
  rocksdb_restore_options_t *restore_options = rocksdb_restore_options_create();
  rocksdb_backup_engine_restore_db_from_latest_backup(g_blockchain_backup_db, g_blockchain_dir,
    g_blockchain_dir, restore_options, &err);

  if (err != NULL)
  {
    LOG_ERROR("Could not restore blockchain database from backup: %s!", err);
    rocksdb_free(err);
    rocksdb_restore_options_destroy(restore_options);
    return 1;
  }

  rocksdb_free(err);
  rocksdb_restore_options_destroy(restore_options);
#endif
  return 0;
}

int restore_blockchain(void)
{
  mtx_lock(&g_blockchain_lock);
  int result = restore_blockchain_nolock();
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int rollback_blockchain_nolock(uint32_t rollback_height)
{
  uint32_t current_block_height = get_block_height_nolock();
  if (rollback_height > current_block_height)
  {
    LOG_WARNING("Could not rollback blockchain to height: %u, current blockchain top block height is: %u!", rollback_height, current_block_height);
    return 1;
  }

  if (current_block_height == rollback_height)
  {
    LOG_INFO("Blockchain already at rollback height: %u, nothing to rollback!", rollback_height);
    return 0;
  }

  // get the new top block after we rollback the blockchain
  block_t *new_top_block = NULL;
  if (rollback_height == 0)
  {
    block_t *genesis_block = get_genesis_block();
    assert(genesis_block != NULL);

    new_top_block = get_block_from_hash_nolock(genesis_block->hash);
    assert(new_top_block != NULL);
  }
  else
  {
    new_top_block = get_block_from_height_nolock(rollback_height - 1);
    assert(new_top_block != NULL);
  }

  char *err = NULL;
#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  leveldb_iterator_t *iterator = leveldb_create_iterator(g_blockchain_db, roptions);
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_writebatch_t *write_batch = leveldb_writebatch_create();
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(g_blockchain_db, roptions);
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_writebatch_t *write_batch = rocksdb_writebatch_create();
#endif
  for (uint32_t i = current_block_height; i > 0; i--)
  {
    if (i == rollback_height)
    {
      break;
    }

    block_t *block = get_block_from_height_nolock(i);
    if (block == NULL)
    {
      LOG_ERROR("Could not rollback blockchain, unknown block at height: %u!", i);
      goto rollback_fail;
    }

    uint8_t block_key[HASH_SIZE + DB_KEY_PREFIX_SIZE_BLOCK];
    get_block_key(block_key, block->hash);

  #ifdef USE_LEVELDB
    leveldb_writebatch_delete(write_batch, (char*)block_key, sizeof(block_key));
  #else
    rocksdb_writebatch_delete(write_batch, (char*)block_key, sizeof(block_key));
  #endif

    // now delete the block's transactions including the unspent transactions...
    for (uint32_t i = 0; i < block->transaction_count; i++)
    {
      transaction_t *tx = block->transactions[i];
      assert(tx != NULL);

      uint8_t tx_key[HASH_SIZE + DB_KEY_PREFIX_SIZE_TX];
      uint8_t unspent_tx_key[HASH_SIZE + DB_KEY_PREFIX_SIZE_UNSPENT_TX];

      get_tx_key(tx_key, tx->id);
      get_unspent_tx_key(unspent_tx_key, tx->id);

    #ifdef USE_LEVELDB
      leveldb_writebatch_delete(write_batch, (char*)tx_key, sizeof(tx_key));
      leveldb_writebatch_delete(write_batch, (char*)unspent_tx_key, sizeof(unspent_tx_key));
    #else
      rocksdb_writebatch_delete(write_batch, (char*)tx_key, sizeof(tx_key));
      rocksdb_writebatch_delete(write_batch, (char*)unspent_tx_key, sizeof(unspent_tx_key));
    #endif
    }

    free_block(block);
  }

#ifdef USE_LEVELDB
  leveldb_write(g_blockchain_db, woptions, write_batch, &err);
#else
  rocksdb_write(g_blockchain_db, woptions, write_batch, &err);
#endif
  if (err != NULL)
  {
    LOG_ERROR("Failed to rollback blockchain, error occurred: %s!", err);
    goto rollback_fail;
  }

  // finally set the new top block provided above
  set_current_block(new_top_block);
  free_block(new_top_block);

  LOG_INFO("Successfully rolled back blockchain to height: %u!", rollback_height);
#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
  leveldb_iter_destroy(iterator);
  leveldb_writeoptions_destroy(woptions);
  leveldb_writebatch_clear(write_batch);
  leveldb_writebatch_destroy(write_batch);
#else
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);
  rocksdb_writeoptions_destroy(woptions);
  rocksdb_writebatch_clear(write_batch);
  rocksdb_writebatch_destroy(write_batch);
#endif
  return 0;

rollback_fail:
#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
  leveldb_iter_destroy(iterator);
  leveldb_writeoptions_destroy(woptions);
  leveldb_writebatch_clear(write_batch);
  leveldb_writebatch_destroy(write_batch);
#else
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);
  rocksdb_writeoptions_destroy(woptions);
  rocksdb_writebatch_clear(write_batch);
  rocksdb_writebatch_destroy(write_batch);
#endif
  return 1;
}

int rollback_blockchain(uint32_t rollback_height)
{
  mtx_lock(&g_blockchain_lock);
  int result = rollback_blockchain_nolock(rollback_height);
  mtx_unlock(&g_blockchain_lock);
  return result;
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
  uint64_t genesis_reward = parameters_get_genesis_reward();
  if (cumulative_emission == 0 && genesis_reward > 0)
  {
    block_reward = genesis_reward;
  }

  return block_reward;
}

uint32_t get_next_work_required_nolock(uint8_t *previous_hash)
{
  if (previous_hash == NULL)
  {
    return parameters_get_pow_initial_difficulty_bits();
  }

  block_t *previous_block = get_block_from_hash(previous_hash);
  assert(previous_block != NULL);

  int32_t previous_height = get_block_height_from_block(previous_block);
  assert(previous_height >= 0);

  if ((previous_height + 1) % parameters_get_difficulty_adjustment_interval() != 0)
  {
    return previous_block->bits;
  }

  uint32_t period_start_block_height = previous_height - (parameters_get_difficulty_adjustment_interval() - 1);
  period_start_block_height = MAX(period_start_block_height, 0);

  block_t *period_start_block = get_block_from_height(period_start_block_height);
  assert(period_start_block != NULL);

  uint32_t actual_time_taken = previous_block->timestamp - period_start_block->timestamp;

  free(previous_block);
  free(period_start_block);

  if (actual_time_taken < parameters_get_pow_target_timespan())
  {
    return previous_block->bits + 1;
  }
  else if (actual_time_taken > parameters_get_pow_target_timespan())
  {
    return previous_block->bits - 1;
  }

  return previous_block->bits;
}

uint32_t get_next_work_required(uint8_t *previous_hash)
{
  mtx_lock(&g_blockchain_lock);
  uint32_t next_work_required = get_next_work_required_nolock(previous_hash);
  mtx_unlock(&g_blockchain_lock);
  return next_work_required;
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

int valid_block_emission(block_t *block, uint32_t block_height)
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

/* After we insert block into blockchain
 * Mark unspent txouts as spent for current txins
 * Add current TX w/ unspent txouts to unspent index
 */
int insert_block_nolock(block_t *block)
{
  assert(block != NULL);
  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_BLOCK];
  get_block_key(key, block->hash);

  buffer_t *buffer = buffer_init();
  serialize_block(buffer, block);
  serialize_transactions_from_block(buffer, block);

  uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

#ifdef USE_LEVELDB
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
#else
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
#endif
  buffer_free(buffer);

  for (uint32_t i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);

    assert(insert_tx_into_index_nolock(key, tx) == 0);
    assert(insert_tx_into_unspent_index_nolock(tx) == 0);

    if (is_generation_tx(tx))
    {
      continue;
    }

    // mark unspent txouts as spent for current txins
    for (uint32_t txin_index = 0; txin_index < tx->txin_count; txin_index++)
    {
      input_transaction_t *txin = tx->txins[txin_index];
      assert(txin != NULL);

      unspent_transaction_t *unspent_tx = get_unspent_tx_from_index_nolock(txin->transaction);
      assert(unspent_tx != NULL);

      if (((unspent_tx->unspent_txout_count - 1) < txin->txout_index) ||
        unspent_tx->unspent_txouts[txin->txout_index] == NULL)
      {
        char *unspent_tx_hash_str = bin2hex(unspent_tx->id, HASH_SIZE);
        LOG_DEBUG("A txin tried to mark a unspent txout: %s as spent, but it was not found!", unspent_tx_hash_str);
        free(unspent_tx_hash_str);
        free_unspent_transaction(unspent_tx);
        continue;
      }
      else
      {
        unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[txin->txout_index];
        assert(unspent_txout != NULL);

        if (unspent_txout->spent == 1)
        {
          char *unspent_tx_hash_str = bin2hex(unspent_tx->id, HASH_SIZE);
          LOG_DEBUG("A txin tried to mark a unspent txout: %s as spent, but it was already spent!", unspent_tx_hash_str);
          free(unspent_tx_hash_str);
          free_unspent_transaction(unspent_tx);
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
          delete_unspent_tx_from_index_nolock(unspent_tx->id);
        }
        else
        {
          insert_unspent_tx_into_index_nolock(unspent_tx);
        }

        free_unspent_transaction(unspent_tx);
      }
    }

  }

  if (err != NULL)
  {
    LOG_ERROR("Could not insert block into blockchain storage: %s!", err);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_writeoptions_destroy(woptions);
  #else
    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
  #endif
    return 1;
  }

  // update our current top block hash in the blockchain
  set_current_block(block);

  // clear the block's transactions from the mempool if any are
  // currently in our mempool, this prevents us from adding transactions
  // to another block that have already been used...
  assert(clear_txs_in_mempool_from_block(block) == 0);

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_writeoptions_destroy(woptions);
#else
  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
#endif
  return 0;
}

int insert_block(block_t *block)
{
  assert(block != NULL);
  mtx_lock(&g_blockchain_lock);
  int result = insert_block_nolock(block);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int validate_and_insert_block_nolock(block_t *block)
{
  assert(block != NULL);

  // verify the block, ensure the block is not an orphan or stale,
  // if the block is the genesis, then we do not need to validate it...
  uint32_t current_block_height = get_block_height_nolock();
  if (valid_block(block) == 0 && current_block_height > 0)
  {
    return 1;
  }

  // ensure we are not adding a block that already exists in the blockchain...
  if (has_block_by_hash(block->hash))
  {
    return 1;
  }

  // check this blocks previous has against our current top block hash
  block_t *current_block = get_current_block();
  if (current_block_height > 0)
  {
    assert(current_block != NULL);
    if (compare_block_hash(block->previous_hash, current_block->hash) == 0)
    {
      goto validate_block_fail;
    }
  }
  else
  {
    // in this case we are validating a genesis block we are adding, if we have
    // any blocks in the blockchain prior to this, then we fail to add the genesis block...
    assert(current_block == NULL);
  }

  // check to see if this block's timestamp is greater than the
  // last median TIMESTAMP_CHECK_WINDOW / 2 block's timestamp...
  if (valid_block_median_timestamp(block) == 0)
  {
    LOG_DEBUG("Could not insert block into blockchain, block has expired timestamp: %u!", block->timestamp);
    goto validate_block_fail;
  }

  // validate the block's generation transaction
  if (valid_block_emission(block, current_block_height) == 0)
  {
    LOG_DEBUG("Could not insert block into blockchain, block has invalid generation transaction!");
    goto validate_block_fail;
  }

  // check the block's difficulty against it's expected value, also check the block's
  // hash to see if it's difficulty is valid...
  uint32_t expected_difficulty = 0;
  if (current_block != NULL)
  {
    expected_difficulty = get_next_work_required(current_block->hash);
  }
  else
  {
    expected_difficulty = get_next_work_required(NULL);
  }

  assert(expected_difficulty > 0);
  if (block->bits != expected_difficulty)
  {
    LOG_DEBUG("Could not insert block into blockchain, block has invalid difficulty: %u expected: %u!", block->bits, expected_difficulty);
    goto validate_block_fail;
  }

  if (check_proof_of_work(block->hash, expected_difficulty) == 0)
  {
    LOG_ERROR("Could not insert block into blockchain, block does not have enough PoW: %u expected: %u!", block->bits, expected_difficulty);
    goto validate_block_fail;
  }

  // as an extra measure, ensure that the block hash is that of
  // what we were expecting provided it's contents...
  assert(valid_block_hash(block) == 1);

  free_block(current_block);
  return insert_block_nolock(block);

validate_block_fail:
  // the current block can only be NULL if we're verifying the genesis block,
  // as the genesis block will never have a previous block in the blockchain...
  if (current_block != NULL)
  {
    free_block(current_block);
  }

  return 1;
}

int validate_and_insert_block(block_t *block)
{
  assert(block != NULL);
  mtx_lock(&g_blockchain_lock);
  int result = validate_and_insert_block_nolock(block);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int is_genesis_block(uint8_t *block_hash)
{
  assert(block_hash != NULL);

  block_t *genesis_block = get_genesis_block();
  assert(genesis_block != NULL);

  return compare_block_hash(block_hash, genesis_block->hash);
}

block_t *get_block_from_hash_nolock(uint8_t *block_hash)
{
  assert(block_hash != NULL);
  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_BLOCK];
  get_block_key(key, block_hash);

  size_t read_len;
#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  uint8_t *serialized_block = (uint8_t*)leveldb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *serialized_block = (uint8_t*)rocksdb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);
#endif

  if (err != NULL || serialized_block == NULL)
  {
    goto block_retrieval_fail;
  }

  buffer_t *buffer = buffer_init_data(0, serialized_block, read_len);
  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);

  // deserialize the block
  block_t *block = NULL;
  if (deserialize_block(buffer_iterator, &block))
  {
    char *block_hash_str = bin2hex(block_hash, HASH_SIZE);
    LOG_ERROR("Failed to deserialize block: %s", block_hash_str);
    free(block_hash_str);

    buffer_iterator_free(buffer_iterator);
    buffer_free(buffer);
    goto block_retrieval_fail;
  }

  // deserialize the block's transactions
  if (deserialize_transactions_to_block(buffer_iterator, block))
  {
    char *block_hash_str = bin2hex(block_hash, HASH_SIZE);
    LOG_ERROR("Failed to deserialize transactions for block: %s, block has no serialized transactions!", block_hash_str);
    free(block_hash_str);

    buffer_iterator_free(buffer_iterator);
    buffer_free(buffer);
    goto block_retrieval_fail;
  }

  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);

#ifdef USE_LEVELDB
  leveldb_free(serialized_block);
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
#else
  rocksdb_free(serialized_block);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
#endif
  return block;

block_retrieval_fail:
#ifdef USE_LEVELDB
  leveldb_free(serialized_block);
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
#else
  rocksdb_free(serialized_block);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
#endif
  return NULL;
}

block_t *get_block_from_hash(uint8_t *block_hash)
{
  assert(block_hash != NULL);
  mtx_lock(&g_blockchain_lock);
  block_t *block = get_block_from_hash_nolock(block_hash);
  mtx_unlock(&g_blockchain_lock);
  return block;
}

block_t *get_block_from_height_nolock(uint32_t height)
{
  uint32_t current_block_height = get_block_height_nolock();
  if (height > current_block_height)
  {
    return NULL;
  }

  if (height == 0)
  {
    block_t *genesis_block = get_genesis_block();
    assert(genesis_block != NULL);

    return get_block_from_hash_nolock(genesis_block->hash);
  }

  block_t *block = get_current_block();
  assert(block != NULL);

  for (uint32_t i = current_block_height; i > 0; i--)
  {
    if (i == height)
    {
      break;
    }

    block_t *previous_block = get_block_from_hash_nolock(block->previous_hash);
    if (previous_block == NULL)
    {
      free_block(block);
      return NULL;
    }

    free_block(block);
    block = previous_block;
  }

  return block;
}

block_t *get_block_from_height(uint32_t height)
{
  mtx_lock(&g_blockchain_lock);
  block_t *block = get_block_from_height_nolock(height);
  mtx_unlock(&g_blockchain_lock);
  return block;
}

int32_t get_block_height_from_hash_nolock(uint8_t *block_hash)
{
  assert(block_hash != NULL);
  uint32_t current_block_height = get_block_height_nolock();

  block_t *block = NULL;
  int32_t block_height = -1;

  for (uint32_t i = 0; i <= current_block_height; i++)
  {
    block = get_block_from_height_nolock(i);
    if (block == NULL)
    {
      break;
    }

    if (compare_block_hash(block->hash, block_hash))
    {
      block_height = i;
      free_block(block);
      break;
    }

    free_block(block);
  }

  return block_height;
}

int32_t get_block_height_from_hash(uint8_t *block_hash)
{
  assert(block_hash != NULL);
  mtx_lock(&g_blockchain_lock);
  int32_t block_height = get_block_height_from_hash_nolock(block_hash);
  mtx_unlock(&g_blockchain_lock);
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

  uint8_t *block_hash = malloc(HASH_SIZE);
  assert(block_hash != NULL);
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

int insert_tx_into_index_nolock(uint8_t *block_key, transaction_t *tx)
{
  assert(block_key != NULL);
  assert(tx != NULL);

  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_TX];
  get_tx_key(key, tx->id);

#ifdef USE_LEVELDB
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)block_key, sizeof(key), &err);
#else
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)block_key, sizeof(key), &err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Could not insert tx into blockchain: %s!", err);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_writeoptions_destroy(woptions);
  #else
    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
  #endif
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_writeoptions_destroy(woptions);
#else
  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
#endif
  return 0;
}

int insert_tx_into_index(uint8_t *block_key, transaction_t *tx)
{
  assert(block_key != NULL);
  assert(tx != NULL);

  mtx_lock(&g_blockchain_lock);
  int result = insert_tx_into_index(block_key, tx);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int insert_tx_into_unspent_index_nolock(transaction_t *tx)
{
  assert(tx != NULL);
  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_UNSPENT_TX];
  get_unspent_tx_key(key, tx->id);

  buffer_t *buffer = buffer_init();
  unspent_transaction_t *unspent_tx = transaction_to_unspent_transaction(tx);
  serialize_unspent_transaction(buffer, unspent_tx);
  free_unspent_transaction(unspent_tx);

  uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

#ifdef USE_LEVELDB
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
#else
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
#endif
  buffer_free(buffer);

  if (err != NULL)
  {
    LOG_ERROR("Could not insert tx into blockchain: %s!", err);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_writeoptions_destroy(woptions);
  #else
    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
  #endif
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_writeoptions_destroy(woptions);
#else
  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
#endif
  return 0;
}

int insert_tx_into_unspent_index(transaction_t *tx)
{
  assert(tx != NULL);
  mtx_lock(&g_blockchain_lock);
  int result = insert_tx_into_unspent_index_nolock(tx);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int insert_unspent_tx_into_index_nolock(unspent_transaction_t *unspent_tx)
{
  assert(unspent_tx != NULL);
  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_UNSPENT_TX];
  get_unspent_tx_key(key, unspent_tx->id);

  buffer_t *buffer = buffer_init();
  serialize_unspent_transaction(buffer, unspent_tx);

  uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

#ifdef USE_LEVELDB
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
#else
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)data, data_len, &err);
#endif
  buffer_free(buffer);

  if (err != NULL)
  {
    LOG_ERROR("Could not insert unspent tx into blockchain: %s!", err);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_writeoptions_destroy(woptions);
  #else
    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
  #endif
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_writeoptions_destroy(woptions);
#else
  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
#endif
  return 0;
}

int insert_unspent_tx_into_index(unspent_transaction_t *unspent_tx)
{
  assert(unspent_tx != NULL);
  mtx_lock(&g_blockchain_lock);
  int result = insert_unspent_tx_into_index_nolock(unspent_tx);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

unspent_transaction_t *get_unspent_tx_from_index_nolock(uint8_t *tx_id)
{
  assert(tx_id != NULL);
  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_UNSPENT_TX];
  get_unspent_tx_key(key, tx_id);

  size_t read_len;
#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  uint8_t *serialized_tx = (uint8_t*)leveldb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *serialized_tx = (uint8_t*)rocksdb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);
#endif

  if (err != NULL || serialized_tx == NULL)
  {
  #ifdef USE_LEVELDB
    leveldb_free(serialized_tx);
    leveldb_free(err);
    leveldb_readoptions_destroy(roptions);
  #else
    rocksdb_free(serialized_tx);
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
  #endif
    return NULL;
  }

  unspent_transaction_t *unspent_tx = unspent_transaction_from_serialized(serialized_tx, read_len);
  assert(unspent_tx != NULL);

#ifdef USE_LEVELDB
  leveldb_free(serialized_tx);
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
#else
  rocksdb_free(serialized_tx);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
#endif
  return unspent_tx;
}

unspent_transaction_t *get_unspent_tx_from_index(uint8_t *tx_id)
{
  assert(tx_id != NULL);
  mtx_lock(&g_blockchain_lock);
  unspent_transaction_t *unspent_tx = get_unspent_tx_from_index_nolock(tx_id);
  mtx_unlock(&g_blockchain_lock);
  return unspent_tx;
}

uint8_t *get_block_hash_from_tx_id_nolock(uint8_t *tx_id)
{
  assert(tx_id != NULL);
  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_TX];
  get_tx_key(key, tx_id);

  size_t read_len;
#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  uint8_t *block_key = (uint8_t*)leveldb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *block_key = (uint8_t*)rocksdb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);
#endif

  if (err != NULL || block_key == NULL)
  {
  #ifdef USE_LEVELDB
    leveldb_free(block_key);
    leveldb_free(err);
    leveldb_readoptions_destroy(roptions);
  #else
    rocksdb_free(block_key);
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
  #endif
    return NULL;
  }

  uint8_t *block_hash = malloc(HASH_SIZE);
  assert(block_hash != NULL);
  memcpy(block_hash, block_key + 1, HASH_SIZE);

#ifdef USE_LEVELDB
  leveldb_free(block_key);
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
#else
  rocksdb_free(block_key);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
#endif
  return block_hash;
}

uint8_t *get_block_hash_from_tx_id(uint8_t *tx_id)
{
  assert(tx_id != NULL);
  mtx_lock(&g_blockchain_lock);
  uint8_t *block_hash = get_block_hash_from_tx_id_nolock(tx_id);
  mtx_unlock(&g_blockchain_lock);
  return block_hash;
}

block_t *get_block_from_tx_id(uint8_t *tx_id)
{
  assert(tx_id != NULL);
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
uint32_t get_block_height_nolock(void)
{
  int32_t block_height = -1;

#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  leveldb_iterator_t *iterator = leveldb_create_iterator(g_blockchain_db, roptions);

  for (leveldb_iter_seek(iterator, DB_KEY_PREFIX_BLOCK, DB_KEY_PREFIX_SIZE_BLOCK);
    leveldb_iter_valid(iterator); leveldb_iter_next(iterator))
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(g_blockchain_db, roptions);

  for (rocksdb_iter_seek(iterator, DB_KEY_PREFIX_BLOCK, DB_KEY_PREFIX_SIZE_BLOCK);
    rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
#endif
  {
    size_t key_length;
  #ifdef USE_LEVELDB
    uint8_t *key = (uint8_t*)leveldb_iter_key(iterator, &key_length);
  #else
    uint8_t *key = (uint8_t*)rocksdb_iter_key(iterator, &key_length);
  #endif
    assert(key != NULL);
    if (key_length > 0 && key[0] == (char)*DB_KEY_PREFIX_BLOCK)
    {
      block_height++;
    }
  }

#ifdef USE_LEVELDB
  leveldb_readoptions_destroy(roptions);
  leveldb_iter_destroy(iterator);
#else
  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);
#endif

  if (block_height < 0)
  {
    return 0;
  }

  return block_height;
}

uint32_t get_block_height(void)
{
  mtx_lock(&g_blockchain_lock);
  int result = get_block_height_nolock();
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int delete_block_from_blockchain_nolock(uint8_t *block_hash)
{
  assert(block_hash != NULL);
  block_t *genesis_block = get_genesis_block();
  assert(genesis_block != NULL);

  if (compare_block_hash(block_hash, genesis_block->hash))
  {
    char *genesis_block_hash = bin2hex(genesis_block->hash, HASH_SIZE);
    LOG_ERROR("Cannot delete genesis block with hash: %s from blockchain!", genesis_block_hash);
    free(genesis_block_hash);
    return 1;
  }

  block_t *block = get_block_from_hash(block_hash);
  assert(block != NULL);

  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_BLOCK];
  get_block_key(key, block_hash);

#ifdef USE_LEVELDB
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);
#else
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);
#endif

  if (err != NULL)
  {
    char *block_hash_str = bin2hex(block_hash, HASH_SIZE);
    LOG_ERROR("Could not delete block: %s from blockchain storage!", block_hash_str);
    free(block_hash_str);

    free_block(block);
  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_writeoptions_destroy(woptions);
  #else
    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
  #endif
    return 0;
  }

  // now delete the block's transactions including the unspent transactions...
  for (uint32_t i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);

    assert(delete_tx_from_index_nolock(tx->id) == 0);
    assert(delete_unspent_tx_from_index_nolock(tx->id) == 0);
  }

  free_block(block);
#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_writeoptions_destroy(woptions);
#else
  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
#endif
  return 1;
}

int delete_block_from_blockchain(uint8_t *block_hash)
{
  assert(block_hash != NULL);
  mtx_lock(&g_blockchain_lock);
  int result = delete_block_from_blockchain_nolock(block_hash);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int delete_tx_from_index_nolock(uint8_t *tx_id)
{
  assert(tx_id != NULL);
  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_TX];
  get_tx_key(key, tx_id);

#ifdef USE_LEVELDB
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);
#else
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);
#endif

  if (err != NULL)
  {
    char *tx_hash_str = bin2hex(tx_id, HASH_SIZE);
    LOG_ERROR("Could not delete tx: %s from index!", tx_hash_str);
    free(tx_hash_str);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_writeoptions_destroy(woptions);
  #else
    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
  #endif
    return 0;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_writeoptions_destroy(woptions);
#else
  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
#endif
  return 1;
}

int delete_tx_from_index(uint8_t *tx_id)
{
  assert(tx_id != NULL);
  mtx_lock(&g_blockchain_lock);
  int result = delete_tx_from_index_nolock(tx_id);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int delete_unspent_tx_from_index_nolock(uint8_t *tx_id)
{
  assert(tx_id != NULL);
  char *err = NULL;
  uint8_t key[HASH_SIZE + DB_KEY_PREFIX_SIZE_UNSPENT_TX];
  get_unspent_tx_key(key, tx_id);

#ifdef USE_LEVELDB
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);
#else
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_blockchain_db, woptions, (char*)key, sizeof(key), &err);
#endif

  if (err != NULL)
  {
    char *unspent_tx_hash_str = bin2hex(tx_id, HASH_SIZE);
    LOG_ERROR("Could not delete unspent tx: %s from unspent index!", unspent_tx_hash_str);
    free(unspent_tx_hash_str);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_writeoptions_destroy(woptions);
  #else
    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
  #endif
    return 0;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_writeoptions_destroy(woptions);
#else
  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
#endif
  return 1;
}

int delete_unspent_tx_from_index(uint8_t *tx_id)
{
  assert(tx_id != NULL);
  mtx_lock(&g_blockchain_lock);
  int result = delete_unspent_tx_from_index_nolock(tx_id);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

int set_top_block_hash_noblock(uint8_t *block_hash)
{
  assert(block_hash != NULL);
  char *err = NULL;
  uint8_t key[DB_KEY_PREFIX_SIZE_TOP_BLOCK];
  get_top_block_key(key);

#ifdef USE_LEVELDB
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)block_hash, HASH_SIZE, &err);
#else
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_blockchain_db, woptions, (char*)key, sizeof(key), (char*)block_hash, HASH_SIZE, &err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Could not set blockchain storage top block hash: %s!", err);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_writeoptions_destroy(woptions);
  #else
    rocksdb_free(err);
    rocksdb_writeoptions_destroy(woptions);
  #endif
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_writeoptions_destroy(woptions);
#else
  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
#endif
  return 0;
}

int set_top_block_hash(uint8_t *block_hash)
{
  assert(block_hash != NULL);
  mtx_lock(&g_blockchain_lock);
  int result = set_top_block_hash_noblock(block_hash);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

uint8_t* get_top_block_hash_noblock(void)
{
  char *err = NULL;
  uint8_t key[DB_KEY_PREFIX_SIZE_TOP_BLOCK];
  get_top_block_key(key);

  size_t read_len;
#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  uint8_t *block_hash = (uint8_t*)leveldb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *block_hash = (uint8_t*)rocksdb_get(g_blockchain_db, roptions, (char*)key, sizeof(key), &read_len, &err);
#endif

  if (err != NULL || block_hash == NULL)
  {
  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_readoptions_destroy(roptions);
  #else
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
  #endif
    return NULL;
  }

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
#else
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
#endif
  return block_hash;
}

uint8_t* get_top_block_hash(void)
{
  mtx_lock(&g_blockchain_lock);
  uint8_t *block_hash = get_top_block_hash_noblock();
  mtx_unlock(&g_blockchain_lock);
  return block_hash;
}

int set_top_block(block_t *block)
{
  assert(block != NULL);
  return set_top_block_hash(block->hash);
}

block_t *get_top_block(void)
{
  uint8_t *block_hash = get_top_block_hash();
  if (block_hash == NULL)
  {
    return NULL;
  }

  block_t *block = get_block_from_hash(block_hash);
  free(block_hash);
  return block;
}

int set_current_block_hash(uint8_t *hash)
{
  assert(hash != NULL);
  memcpy(g_blockchain_current_block_hash, hash, HASH_SIZE);
  return 0;
}

uint8_t *get_current_block_hash(void)
{
  return g_blockchain_current_block_hash;
}

int set_current_block(block_t *block)
{
  assert(block != NULL);
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
  assert(block_hash != NULL);
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

  return 0;
}

uint32_t get_blocks_since_block(block_t *block)
{
  assert(block != NULL);
  return get_blocks_since_hash(block->hash);
}

void get_tx_key(uint8_t *buffer, uint8_t *tx_id)
{
  assert(buffer != NULL);
  assert(tx_id != NULL);
  memcpy(buffer, DB_KEY_PREFIX_TX, DB_KEY_PREFIX_SIZE_TX);
  memcpy(buffer + DB_KEY_PREFIX_SIZE_TX, tx_id, HASH_SIZE);
}

void get_unspent_tx_key(uint8_t *buffer, uint8_t *tx_id)
{
  assert(buffer != NULL);
  assert(tx_id != NULL);
  memcpy(buffer, DB_KEY_PREFIX_UNSPENT_TX, DB_KEY_PREFIX_SIZE_UNSPENT_TX);
  memcpy(buffer + DB_KEY_PREFIX_SIZE_UNSPENT_TX, tx_id, HASH_SIZE);
}

void get_block_key(uint8_t *buffer, uint8_t *block_hash)
{
  assert(buffer != NULL);
  assert(block_hash != NULL);
  memcpy(buffer, DB_KEY_PREFIX_BLOCK, DB_KEY_PREFIX_SIZE_BLOCK);
  memcpy(buffer + DB_KEY_PREFIX_SIZE_BLOCK, block_hash, HASH_SIZE);
}

void get_top_block_key(uint8_t *buffer)
{
  assert(buffer != NULL);
  memcpy(buffer, DB_KEY_PREFIX_TOP_BLOCK, DB_KEY_PREFIX_SIZE_TOP_BLOCK);
}

int get_unspent_transactions_for_address_nolock(uint8_t *address, vec_void_t *unspent_txs, uint32_t *num_unspent_txs)
{
  assert(address != NULL);
  assert(unspent_txs != NULL);

#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  leveldb_iterator_t *iterator = leveldb_create_iterator(g_blockchain_db, roptions);

  for (leveldb_iter_seek(iterator, DB_KEY_PREFIX_UNSPENT_TX, DB_KEY_PREFIX_SIZE_UNSPENT_TX);
    leveldb_iter_valid(iterator); leveldb_iter_next(iterator))
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(g_blockchain_db, roptions);

  for (rocksdb_iter_seek(iterator, DB_KEY_PREFIX_UNSPENT_TX, DB_KEY_PREFIX_SIZE_UNSPENT_TX);
    rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
#endif
  {
    size_t key_length;
  #ifdef USE_LEVELDB
    char *key = (char*)leveldb_iter_key(iterator, &key_length);
    assert(key != NULL);
  #else
    char *key = (char*)rocksdb_iter_key(iterator, &key_length);
    assert(key != NULL);
  #endif

    if (key_length > 0 && key[0] == (char)*DB_KEY_PREFIX_UNSPENT_TX)
    {
      size_t data_len;
    #ifdef USE_LEVELDB
      uint8_t *data = (uint8_t*)leveldb_iter_value(iterator, &data_len);
      assert(data != NULL);
    #else
      uint8_t *data = (uint8_t*)rocksdb_iter_value(iterator, &data_len);
      assert(data != NULL);
    #endif

      unspent_transaction_t *unspent_tx = unspent_transaction_from_serialized(data, data_len);
      assert(unspent_tx != NULL);

      int has_unspent_txout = 0;
      for (uint32_t i = 0; i < unspent_tx->unspent_txout_count; i++)
      {
        unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[i];
        assert(unspent_txout != NULL);

        if (compare_addresses(unspent_txout->address, address) == 0)
        {
          continue;
        }

        if (unspent_txout->spent == 1)
        {
          continue;
        }

        has_unspent_txout = 1;
        break;
      }

      if (has_unspent_txout)
      {
        assert(vec_push(unspent_txs, unspent_tx) == 0);
        *num_unspent_txs += 1;
      }
      else
      {
        // free the unspent transaction since this transaction was not
        // relevant to the address we are looking for and/or this transaction
        // does not have any unspent transaction outputs...
        free_unspent_transaction(unspent_tx);
      }
    }
  }

#ifdef USE_LEVELDB
  leveldb_readoptions_destroy(roptions);
  leveldb_iter_destroy(iterator);
#else
  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);
#endif

  return 0;
}

int get_unspent_transactions_for_address(uint8_t *address, vec_void_t *unspent_txs, uint32_t *num_unspent_txs)
{
  mtx_lock(&g_blockchain_lock);
  int result = get_unspent_transactions_for_address_nolock(address, unspent_txs, num_unspent_txs);
  mtx_unlock(&g_blockchain_lock);
  return result;
}

uint64_t get_balance_for_address_nolock(uint8_t *address)
{
  assert(address != NULL);
  uint64_t balance = 0;

  vec_void_t unspent_txs;
  vec_init(&unspent_txs);

  uint32_t num_unspent_txs = 0;
  assert(get_unspent_transactions_for_address_nolock(address, &unspent_txs, &num_unspent_txs) == 0);

  void *value = NULL;
  int index = 0;
  vec_foreach(&unspent_txs, value, index)
  {
    unspent_transaction_t *unspent_tx = (unspent_transaction_t*)value;
    assert(unspent_tx != NULL);

    for (uint32_t i = 0; i < unspent_tx->unspent_txout_count; i++)
    {
      unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[i];
      assert(unspent_txout != NULL);

      if (compare_addresses(unspent_txout->address, address) == 0)
      {
        continue;
      }

      if (unspent_txout->spent == 1)
      {
        continue;
      }

      balance += unspent_txout->amount;
    }

    free_unspent_transaction(unspent_tx);
  }

  vec_deinit(&unspent_txs);
  return balance;
}

uint64_t get_balance_for_address(uint8_t *address)
{
  mtx_lock(&g_blockchain_lock);
  uint64_t balance = get_balance_for_address_nolock(address);
  mtx_unlock(&g_blockchain_lock);
  return balance;
}
