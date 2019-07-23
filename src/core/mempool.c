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
#include <stdint.h>
#include <assert.h>
#include <time.h>

#include <array.h>

#include "common/logger.h"
#include "common/task.h"
#include "common/tinycthread.h"
#include "common/util.h"

#include "block.h"
#include "mempool.h"
#include "transaction.h"

static mtx_t g_mempool_lock;
static int g_mempool_initialized = 0;

static Array *g_mempool_transactions = NULL;
static int g_mempool_num_transactions = 0;

static task_t *g_mempool_flush_task = NULL;

mempool_entry_t* init_mempool_entry(void)
{
  mempool_entry_t *mempool_entry = malloc(sizeof(mempool_entry_t));
  assert(mempool_entry != NULL);
  mempool_entry->tx = NULL;
  mempool_entry->received_ts = 0;
  return mempool_entry;
}

void free_mempool_entry(mempool_entry_t *mempool_entry)
{
  assert(mempool_entry != NULL);
  free(mempool_entry);
}

mempool_entry_t* get_mempool_entry_from_mempool(uint8_t *tx_hash)
{
  void *val = NULL;
  ARRAY_FOREACH(val, g_mempool_transactions,
  {
    mempool_entry_t *mempool_entry = (mempool_entry_t*)val;
    assert(mempool_entry != NULL);

    transaction_t *tx = mempool_entry->tx;
    assert(tx != NULL);

    if (compare_hash(tx->id, tx_hash))
    {
      return mempool_entry;
    }
  })

  return NULL;
}

transaction_t* get_tx_from_mempool(uint8_t *tx_hash)
{
  mempool_entry_t *mempool_entry = get_mempool_entry_from_mempool(tx_hash);
  if (mempool_entry == NULL)
  {
    return NULL;
  }

  return mempool_entry->tx;
}

int is_tx_in_mempool_nolock(transaction_t *tx)
{
  assert(tx != NULL);
  return get_tx_from_mempool(tx->id) != NULL;
}

int is_tx_in_mempool(transaction_t *tx)
{
  mtx_lock(&g_mempool_lock);
  int result = is_tx_in_mempool_nolock(tx);
  mtx_unlock(&g_mempool_lock);
  return result;
}

int add_tx_to_mempool_nolock(transaction_t *tx)
{
  assert(tx != NULL);
  mempool_entry_t *mempool_entry = init_mempool_entry();
  mempool_entry->tx = tx;
  mempool_entry->received_ts = get_current_time();

  if (array_add(g_mempool_transactions, mempool_entry) != CC_OK)
  {
    free_mempool_entry(mempool_entry);
    return 1;
  }

  g_mempool_num_transactions++;
  return 0;
}

int add_tx_to_mempool(transaction_t *tx)
{
  mtx_lock(&g_mempool_lock);
  int result = add_tx_to_mempool_nolock(tx);
  mtx_unlock(&g_mempool_lock);
  return result;
}

int validate_and_add_tx_to_mempool_nolock(transaction_t *tx)
{
  assert(tx != NULL);
  if (valid_transaction(tx) == 0)
  {
    return 1;
  }

  if (is_coinbase_tx(tx))
  {
    return 1;
  }

  if (is_tx_in_mempool_nolock(tx))
  {
    return 1;
  }

  return add_tx_to_mempool_nolock(tx);
}

int validate_and_add_tx_to_mempool(transaction_t *tx)
{
  mtx_lock(&g_mempool_lock);
  int result = validate_and_add_tx_to_mempool_nolock(tx);
  mtx_unlock(&g_mempool_lock);
  return result;
}

int remove_tx_from_mempool_nolock(transaction_t *tx)
{
  assert(tx != NULL);
  if (is_tx_in_mempool_nolock(tx) == 0)
  {
    return 1;
  }

  mempool_entry_t *mempool_entry = get_mempool_entry_from_mempool(tx->id);
  assert(mempool_entry != NULL);

  if (array_remove(g_mempool_transactions, mempool_entry, NULL) != CC_OK)
  {
    return 1;
  }

  g_mempool_num_transactions--;
  free_mempool_entry(mempool_entry);
  return 0;
}

int remove_tx_from_mempool(transaction_t *tx)
{
  mtx_lock(&g_mempool_lock);
  int result = remove_tx_from_mempool_nolock(tx);
  mtx_unlock(&g_mempool_lock);
  return result;
}

transaction_t* pop_tx_from_mempool_nolock(void)
{
  void *val = NULL;
  assert(array_remove_at(g_mempool_transactions, 0, &val) == CC_OK);

  mempool_entry_t *mempool_entry = (mempool_entry_t*)val;
  assert(mempool_entry != NULL);

  transaction_t *tx = mempool_entry->tx;
  assert(tx != NULL);

  g_mempool_num_transactions--;
  free_mempool_entry(mempool_entry);
  return tx;
}

transaction_t* pop_tx_from_mempool(void)
{
  mtx_lock(&g_mempool_lock);
  transaction_t *tx = pop_tx_from_mempool_nolock();
  mtx_unlock(&g_mempool_lock);
  return tx;
}

uint64_t get_num_txs_in_mempool(void)
{
  return g_mempool_num_transactions;
}

int fill_block_with_txs_from_mempool_nolock(block_t *block)
{
  assert(block != NULL);

  // skip over the generation tx
  uint32_t tx_index = 1;

  void *val = NULL;
  ARRAY_FOREACH(val, g_mempool_transactions,
  {
    mempool_entry_t *mempool_entry = (mempool_entry_t*)val;
    assert(mempool_entry != NULL);

    transaction_t *tx = mempool_entry->tx;
    assert(tx != NULL);

    // check the new block header size
    uint32_t block_header_size = get_block_header_size(block) + get_tx_header_size(tx);
    if (block_header_size >= MAX_BLOCK_SIZE)
    {
      break;
    }

    assert(add_transaction_to_block(block, tx, tx_index) == 0);
    tx_index++;
  })

  return 0;
}

int fill_block_with_txs_from_mempool(block_t *block)
{
  assert(block != NULL);
  mtx_lock(&g_mempool_lock);
  int result = fill_block_with_txs_from_mempool_nolock(block);
  mtx_unlock(&g_mempool_lock);
  return result;
}

int clear_txs_in_mempool_from_block_nolock(block_t *block)
{
  assert(block != NULL);
  for (uint32_t i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);

    remove_tx_from_mempool_nolock(tx);
  }

  return 0;
}

int clear_txs_in_mempool_from_block(block_t *block)
{
  assert(block != NULL);
  mtx_lock(&g_mempool_lock);
  int result = clear_txs_in_mempool_from_block_nolock(block);
  mtx_unlock(&g_mempool_lock);
  return result;
}

int clear_expired_txs_in_mempool_nolock(void)
{
  Array *txs_to_remove;
  assert(array_new(&txs_to_remove) == CC_OK);

  void *val = NULL;
  ARRAY_FOREACH(val, g_mempool_transactions,
  {
    mempool_entry_t *mempool_entry = (mempool_entry_t*)val;
    assert(mempool_entry != NULL);

    transaction_t *tx = mempool_entry->tx;
    assert(tx != NULL);

    int remove_tx = 0;
    uint32_t tx_age = get_current_time() - mempool_entry->received_ts;
    if (valid_transaction(tx) == 0)
    {
      remove_tx = 1;
    }
    else if (tx_age > MEMPOOL_TX_EXPIRE_TIME)
    {
      char *tx_hash_str = bin2hex(tx->id, HASH_SIZE);
      LOG_DEBUG("Removing transaction: %s from mempool due to expired age: %u!", tx_hash_str, tx_age);
      free(tx_hash_str);
      remove_tx = 1;
    }

    if (remove_tx)
    {
      assert(array_add(txs_to_remove, tx) == CC_OK);
    }
  })

  val = NULL;
  ARRAY_FOREACH(val, txs_to_remove,
  {
    transaction_t *tx = (transaction_t*)val;
    assert(tx != NULL);

    assert(remove_tx_from_mempool_nolock(tx) == 0);
    free_transaction(tx);
  })

  array_destroy(txs_to_remove);
  return 0;
}

int clear_expired_txs_in_mempool_noblock(void)
{
  if (mtx_trylock(&g_mempool_lock) == thrd_error)
  {
    return 0;
  }

  int result = clear_expired_txs_in_mempool_nolock();
  mtx_unlock(&g_mempool_lock);
  return result;
}

int clear_expired_txs_in_mempool(void)
{
  mtx_lock(&g_mempool_lock);
  int result = clear_expired_txs_in_mempool_nolock();
  mtx_unlock(&g_mempool_lock);
  return result;
}

static task_result_t flush_mempool(task_t *task, va_list args)
{
  assert(clear_expired_txs_in_mempool_noblock() == 0);
  return TASK_RESULT_WAIT;
}

int start_mempool(void)
{
  if (g_mempool_initialized)
  {
    return 1;
  }

  mtx_init(&g_mempool_lock, mtx_recursive);
  assert(array_new(&g_mempool_transactions) == CC_OK);

  g_mempool_num_transactions = 0;
  g_mempool_flush_task = add_task(flush_mempool, FLUSH_MEMPOOL_TASK_DELAY);
  g_mempool_initialized = 1;
  return 0;
}

int stop_mempool(void)
{
  if (g_mempool_initialized == 0)
  {
    return 1;
  }

  remove_task(g_mempool_flush_task);
  mtx_destroy(&g_mempool_lock);
  array_destroy(g_mempool_transactions);

  g_mempool_num_transactions = 0;
  g_mempool_flush_task = NULL;
  g_mempool_initialized = 0;
  return 0;
}
