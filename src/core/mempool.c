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

#include <stdint.h>
#include <memory.h>
#include <assert.h>
#include <time.h>

#include "common/logger.h"
#include "common/task.h"
#include "common/tinycthread.h"
#include "common/util.h"
#include "common/vec.h"

#include "block.h"
#include "mempool.h"
#include "transaction.h"

static mtx_t g_mempool_lock;
static int g_mempool_initialized = 0;

static vec_void_t g_mempool_transactions;
static int g_mempool_num_transactions;

static task_t *g_mempool_flush_task = NULL;

int start_mempool(void)
{
  if (g_mempool_initialized)
  {
    return 1;
  }

  mtx_init(&g_mempool_lock, mtx_recursive);
  vec_init(&g_mempool_transactions);

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
  vec_deinit(&g_mempool_transactions);

  g_mempool_num_transactions = 0;
  g_mempool_flush_task = NULL;
  g_mempool_initialized = 0;
  return 0;
}

mempool_entry_t* init_mempool_entry(void)
{
  mempool_entry_t *mempool_entry = malloc(sizeof(mempool_entry_t));
  mempool_entry->tx = NULL;
  mempool_entry->received_ts = 0;
  return mempool_entry;
}

int free_mempool_entry(mempool_entry_t *mempool_entry)
{
  assert(mempool_entry != NULL);
  free(mempool_entry);
  return 0;
}

mempool_entry_t* get_mempool_entry_from_mempool(uint8_t *tx_hash)
{
  mempool_entry_t *found_mempool_entry = NULL;

  // find the mempool entry by iterating through all of the pointers
  // in the vector array, find the mempool entry that has the same
  // transaction pointer memory address...
  void *value = NULL;
  int index = 0;
  vec_foreach(&g_mempool_transactions, value, index)
  {
    mempool_entry_t *mempool_entry = (mempool_entry_t*)value;
    assert(mempool_entry != NULL);

    transaction_t *tx = mempool_entry->tx;
    assert(tx != NULL);

    if (compare_transaction_hash(tx->id, tx_hash))
    {
      found_mempool_entry = mempool_entry;
      break;
    }
  }

  return found_mempool_entry;
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
  if (valid_transaction(tx) == 0)
  {
    return 1;
  }

  if (is_tx_in_mempool_nolock(tx))
  {
    return 1;
  }

  mempool_entry_t *mempool_entry = init_mempool_entry();
  mempool_entry->tx = tx;
  mempool_entry->received_ts = get_current_time();

  assert(vec_push(&g_mempool_transactions, mempool_entry) == 0);
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

int remove_tx_from_mempool_nolock(transaction_t *tx)
{
  assert(tx != NULL);
  if (is_tx_in_mempool_nolock(tx) == 0)
  {
    return 1;
  }

  mempool_entry_t *mempool_entry = get_mempool_entry_from_mempool(tx->id);
  assert(mempool_entry != NULL);
  vec_remove(&g_mempool_transactions, mempool_entry);
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
  mempool_entry_t *mempool_entry = vec_pop(&g_mempool_transactions);
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

  vec_void_t transactions;
  vec_init(&transactions);

  void *value = NULL;
  int index = 0;
  vec_foreach(&g_mempool_transactions, value, index)
  {
    mempool_entry_t *mempool_entry = (mempool_entry_t*)value;
    assert(mempool_entry != NULL);

    transaction_t *tx = mempool_entry->tx;
    assert(tx != NULL);

    // check the new block header size
    uint32_t block_header_size = get_block_header_size(block) + get_tx_header_size(tx);
    if (block_header_size > MAX_BLOCK_SIZE)
    {
      break;
    }

    assert(vec_push(&transactions, tx) == 0);
  }

  value = NULL;
  index = 0;

  // skip over the generation tx
  uint32_t tx_index = 1;
  vec_foreach(&transactions, value, index)
  {
    transaction_t *tx = (transaction_t*)value;
    assert(tx != NULL);

    assert(add_transaction_to_block(block, tx, tx_index) == 0);
    assert(remove_tx_from_mempool_nolock(tx) == 0);
    tx_index++;
  }

  vec_deinit(&transactions);
  return 0;
}

int fill_block_with_txs_from_mempool(block_t *block)
{
  mtx_lock(&g_mempool_lock);
  int result = fill_block_with_txs_from_mempool_nolock(block);
  mtx_unlock(&g_mempool_lock);
  return result;
}

int clear_expired_txs_in_mempool_nolock(void)
{
  vec_void_t transactions_to_remove;
  vec_init(&transactions_to_remove);

  void *value = NULL;
  int index = 0;
  vec_foreach(&g_mempool_transactions, value, index)
  {
    mempool_entry_t *mempool_entry = (mempool_entry_t*)value;
    assert(mempool_entry != NULL);

    transaction_t *tx = mempool_entry->tx;
    assert(tx != NULL);

    uint32_t tx_age = get_current_time() - mempool_entry->received_ts;
    if (tx_age > MEMPOOL_TX_EXPIRE_TIME)
    {
      LOG_DEBUG("Removing transaction: %s from mempool due to expired age: %u!", hash_to_str(tx->id), tx_age);
      assert(vec_push(&transactions_to_remove, tx) == 0);
    }
  }

  value = NULL;
  index = 0;
  vec_foreach(&transactions_to_remove, value, index)
  {
    transaction_t *tx = (transaction_t*)value;
    assert(tx != NULL);

    assert(remove_tx_from_mempool_nolock(tx) == 0);
    free_transaction(tx);
  }

  vec_deinit(&transactions_to_remove);
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

task_result_t flush_mempool(task_t *task, va_list args)
{
  assert(clear_expired_txs_in_mempool_noblock() == 0);
  return TASK_RESULT_WAIT;
}
