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

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include <rocksdb/c.h>

#include "vulkan.pb-c.h"
#include "block.h"
#include "chain.h"

static uint8_t g_chain_current_block_hash[32];
static int g_chain_is_open = 0;
static rocksdb_t *g_chain_db = NULL;

int open_blockchain()
{
  if (g_chain_is_open)
  {
    return 0;
  }

  char *err = NULL;
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(options, 1);
  g_chain_db = rocksdb_open(options, "blockchain", &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not open blockchain database: %s\n", err);
    return 1;
  }

  block_t *test_block = get_block_from_blockchain(genesis_block.hash);
  if (test_block == NULL)
  {
    insert_block_into_blockchain(&genesis_block);
  }
  else
  {
    free_block(test_block);
  }

  g_chain_is_open = 1;

  rocksdb_free(err);
  rocksdb_free(options);
  return 0;
}

int close_blockchain()
{
  if (g_chain_is_open)
  {
    rocksdb_close(g_chain_db);
    g_chain_is_open = 0;
    return 0;
  }
  else
  {
    return 0;
  }
}

int init_blockchain()
{
  open_blockchain();
  return 0;
}

/* After we insert block into blockchain
 * Mark unspent txouts as spent for current txins
 * Add current TX w/ unspent txouts to unspent index
 */
int insert_block_into_blockchain(block_t *block)
{
  char *err = NULL;
  uint8_t key[33];
  get_block_key(key, block->hash);

  uint8_t *buffer = NULL;
  uint32_t buffer_len = 0;

  block_to_serialized(&buffer, &buffer_len, block);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_chain_db, woptions, (char *) key, 33, (char *) buffer, buffer_len, &err);

  free(buffer);

  for (int i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];

    insert_tx_into_index(key, tx);
    insert_unspent_tx_into_index(tx);

    if (is_generation_tx(tx))
    {
      continue;
    }

    // Mark unspent txouts as spent for current txins
    for (int txin_index = 0; txin_index < tx->txin_count; txin_index++)
    {
      input_transaction_t *txin = tx->txins[txin_index];
      PUnspentTransaction *unspent_tx = get_unspent_tx_from_index(txin->transaction);

      if (((unspent_tx->n_unspent_txouts - 1) < txin->txout_index) || unspent_tx->unspent_txouts[txin->txout_index] == NULL)
      {
        free_proto_unspent_transaction(unspent_tx);
        fprintf(stderr, "A txin tried to mark a unspent txout as spent, but it was not found\n");
        continue;
      }
      else
      {
        PUnspentOutputTransaction *unspent_txout = unspent_tx->unspent_txouts[txin->txout_index];
        if (unspent_txout->spent == 1)
        {
          free_proto_unspent_transaction(unspent_tx);
          fprintf(stderr, "A txin tried to mark a unspent txout as spent, but it was already spent\n");
          continue;
        }

        unspent_txout->spent = 1;

        int spent_txs = 0;
        for (int j = 0; j < unspent_tx->n_unspent_txouts; j++)
        {
          if (unspent_txout->spent == 1)
          {
            spent_txs++;
          }
        }

        if (spent_txs == unspent_tx->n_unspent_txouts)
        {
          delete_unspent_tx_from_index(unspent_tx->id.data);
        }
        else
        {
          insert_proto_unspent_tx_into_index(unspent_tx);
        }

        free_proto_unspent_transaction(unspent_tx);
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

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 1;
}

block_t *get_block_from_blockchain(uint8_t *block_hash)
{
  char *err = NULL;
  uint8_t key[33];
  get_block_key(key, block_hash);

  size_t read_len;
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *serialized_block = (uint8_t *) rocksdb_get(g_chain_db, roptions, (char *) key, 33, &read_len, &err);

  if (err != NULL || serialized_block == NULL)
  {
    fprintf(stderr, "Could not retrieve block from blockchain: %s\n", err);

    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    return NULL;
  }

  block_t *block = block_from_serialized(serialized_block, read_len);

  rocksdb_free(serialized_block);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  return block;
}

int insert_tx_into_index(uint8_t *block_key, transaction_t *tx)
{
  char *err = NULL;
  uint8_t key[33];
  get_tx_key(key, tx->id);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_chain_db, woptions, (char *) key, 33, (char *) block_key, 33, &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not insert tx into blockchain: %s\n", err);
    return 1;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 0;
}

int insert_unspent_tx_into_index(transaction_t *tx)
{
  char *err = NULL;
  uint8_t key[33];
  get_unspent_tx_key(key, tx->id);

  uint8_t *buffer = NULL;
  uint32_t buffer_len = 0;
  unspent_transaction_to_serialized(&buffer, &buffer_len, tx);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_chain_db, woptions, (char *) key, 33, (char *) buffer, buffer_len, &err);

  free(buffer);

  if (err != NULL)
  {
    fprintf(stderr, "Could not insert tx into blockchain: %s\n", err);
    return 1;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 0;
}

int insert_proto_unspent_tx_into_index(PUnspentTransaction *tx)
{
  char *err = NULL;
  uint8_t key[33];
  get_unspent_tx_key(key, tx->id.data);

  uint8_t *buffer = NULL;
  uint32_t buffer_len = 0;
  proto_unspent_transaction_to_serialized(&buffer, &buffer_len, tx);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(g_chain_db, woptions, (char *) key, 33, (char *) buffer, buffer_len, &err);

  free(buffer);

  if (err != NULL)
  {
    fprintf(stderr, "Could not insert tx into blockchain: %s\n", err);
    return 1;
  }

  rocksdb_free(err);
  rocksdb_writeoptions_destroy(woptions);
  return 0;
}


PUnspentTransaction *get_unspent_tx_from_index(uint8_t *tx_id)
{
  char *err = NULL;
  uint8_t key[33];
  get_unspent_tx_key(key, tx_id);

  size_t read_len;
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *serialized_tx = (uint8_t *) rocksdb_get(g_chain_db, roptions, (char *) key, 33, &read_len, &err);

  if (err != NULL || serialized_tx == NULL)
  {
    fprintf(stderr, "Could not retrieve unspent tx from index\n");

    rocksdb_free(err);
    rocksdb_free(roptions);
    return NULL;
  }

  PUnspentTransaction *tx = unspent_transaction_from_serialized(serialized_tx, read_len);

  rocksdb_free(serialized_tx);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  return tx;
}

uint8_t *get_block_hash_from_tx_id(uint8_t *tx_id)
{
  char *err = NULL;
  uint8_t key[33];
  get_tx_key(key, tx_id);

  size_t read_len;
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *block_key = (uint8_t *) rocksdb_get(g_chain_db, roptions, (char *) key, 33, &read_len, &err);

  if (err != NULL || block_key == NULL)
  {
    fprintf(stderr, "Could not retrieve block from tx id\n");

    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    return NULL;
  }

  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);

  uint8_t *block_hash = malloc(sizeof(uint8_t) * 32);
  memcpy(block_hash, block_key + 1, 32);

  rocksdb_free(block_key);

  return block_hash;
}

block_t *get_block_from_tx_id(uint8_t *tx_id)
{
  uint8_t *block_hash = get_block_hash_from_tx_id(tx_id);
  if (block_hash == NULL)
  {
    return NULL;
  }

  return get_block_from_blockchain(block_hash);
}

/*
 * This function gets the block height by iterating all keys in the blockchain g_chain_db.
 * All blocks get prefixed with "b + <block_hash>".
 *
 * For the sake of dev time, only blocks in the g_chain_db are valid + main chain.
 */
uint32_t get_block_height()
{
  uint32_t block_height = 0;

  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(g_chain_db, roptions);

  for (rocksdb_iter_seek(iterator, "b", 1); rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
  {
    size_t key_length;
    uint8_t *key = (uint8_t *) rocksdb_iter_key(iterator, &key_length);

    if (key_length > 0 && key[0] == 'b')
    {
      block_height++;
    }
  }

  rocksdb_readoptions_destroy(roptions);
  rocksdb_iter_destroy(iterator);

  return block_height;
}

int delete_block_from_blockchain(uint8_t *block_hash)
{
  char *err = NULL;
  uint8_t key[33];
  get_block_key(key, block_hash);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_chain_db, woptions, (char *) key, 33, &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not delete block from blockchain\n");
    rocksdb_writeoptions_destroy(woptions);
    free(err);

    return 0;
  }

  rocksdb_writeoptions_destroy(woptions);
  return 1;
}

int delete_tx_from_index(uint8_t *tx_id)
{
  char *err = NULL;
  uint8_t key[33];
  get_tx_key(key, tx_id);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_chain_db, woptions, (char *) key, 33, &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not delete tx from index\n");
    rocksdb_writeoptions_destroy(woptions);
    free(err);
    return 0;
  }

  rocksdb_writeoptions_destroy(woptions);
  return 1;
}

int delete_unspent_tx_from_index(uint8_t *tx_id)
{
  char *err = NULL;
  uint8_t key[33];
  get_unspent_tx_key(key, tx_id);

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_delete(g_chain_db, woptions, (char *) key, 33, &err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not delete tx from unspent index\n");

    rocksdb_writeoptions_destroy(woptions);
    free(err);
    return 0;
  }

  rocksdb_writeoptions_destroy(woptions);
  return 1;
}

uint8_t *get_current_block_hash()
{
  return g_chain_current_block_hash;
}

int set_current_block_hash(uint8_t *hash)
{
  memcpy(g_chain_current_block_hash, hash, 32);
  return 0;
}

int get_tx_key(uint8_t *buffer, uint8_t *tx_id)
{
  buffer[0] = 't';
  memcpy(buffer + 1, tx_id, 32);
  return 0;
}

int get_unspent_tx_key(uint8_t *buffer, uint8_t *tx_id)
{
  buffer[0] = 'c';
  memcpy(buffer + 1, tx_id, 32);
  return 0;
}

int get_block_key(uint8_t *buffer, uint8_t *block_hash)
{
  buffer[0] = 'b';
  memcpy(buffer + 1, block_hash, 32);
  return 0;
}

uint32_t get_balance_for_address(uint8_t *address)
{
  uint32_t balance = 0;

  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  rocksdb_iterator_t *iterator = rocksdb_create_iterator(g_chain_db, roptions);

  for (rocksdb_iter_seek(iterator, "c", 1); rocksdb_iter_valid(iterator); rocksdb_iter_next(iterator))
  {
    size_t key_length;
    char *key = (char *) rocksdb_iter_key(iterator, &key_length);

    if (key_length > 0 && key[0] == 'c')
    {
      size_t value_length;
      uint8_t *value = (uint8_t *) rocksdb_iter_value(iterator, &value_length);

      PUnspentTransaction *tx = unspent_transaction_from_serialized(value, value_length);

      for (int i = 0; i < tx->n_unspent_txouts; i++)
      {
        PUnspentOutputTransaction *unspent_txout = tx->unspent_txouts[i];
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
