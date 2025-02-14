// Copyright (c) 2019-2022, The Vulkan Developers.
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

#include <cc_array.h>

#include "common/logger.h"
#include "common/task.h"
#include "common/tinycthread.h"
#include "common/util.h"

#include "block.h"
#include "mempool.h"
#include "transaction.h"
#include "blockchain.h"

static mtx_t g_mempool_lock;
static int g_mempool_initialized = 0;

static CC_Array *g_mempool_transactions = NULL;
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
  CC_ArrayIter iter;
  cc_array_iter_init(&iter, g_mempool_transactions);

  void *el;
  while (cc_array_iter_next(&iter, (void*) &el) != CC_ITER_END)
  {
    mempool_entry_t *mempool_entry = (mempool_entry_t*)el;
    assert(mempool_entry != NULL);

    transaction_t *tx = mempool_entry->tx;
    assert(tx != NULL);

    if (compare_hash(tx->id, tx_hash))
    {
      return mempool_entry;
    }
  }

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

  // Check for double spending attempts from the same address
  for (uint32_t i = 0; i < tx->txin_count; i++)
  {
    input_transaction_t *txin = tx->txins[i];
    assert(txin != NULL);

    CC_ArrayIter iter;
    cc_array_iter_init(&iter, g_mempool_transactions);

    void *el;
    while (cc_array_iter_next(&iter, (void*) &el) != CC_ITER_END)
    {
      mempool_entry_t *mempool_entry = (mempool_entry_t*)el;
      assert(mempool_entry != NULL);

      transaction_t *mempool_tx = mempool_entry->tx;
      assert(mempool_tx != NULL);

      for (uint32_t j = 0; j < mempool_tx->txin_count; j++)
      {
        input_transaction_t *mempool_txin = mempool_tx->txins[j];
        assert(mempool_txin != NULL);

        if (compare_hash(txin->transaction, mempool_txin->transaction) == 0 &&
            txin->txout_index == mempool_txin->txout_index)
        {
          // Transaction attempts to spend an input already in use in the mempool
          return 1;
        }
      }
    }
  }

  mempool_entry_t *mempool_entry = init_mempool_entry();
  mempool_entry->tx = tx;
  mempool_entry->received_ts = get_current_time();

  if (cc_array_add(g_mempool_transactions, mempool_entry) != CC_OK)
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

  if (cc_array_remove(g_mempool_transactions, mempool_entry, NULL) != CC_OK)
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
  int r = cc_array_remove_at(g_mempool_transactions, 0, &val);
  assert(r == CC_OK);

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

  CC_ArrayIter iter;
  cc_array_iter_init(&iter, g_mempool_transactions);

  void *el;
  while (cc_array_iter_next(&iter, (void*) &el) != CC_ITER_END)
  {
    mempool_entry_t *mempool_entry = (mempool_entry_t*)el;
    assert(mempool_entry != NULL);

    transaction_t *tx = mempool_entry->tx;
    assert(tx != NULL);

    // check the new block header size
    uint32_t block_header_size = get_block_header_size(block) + get_tx_header_size(tx);
    if (block_header_size >= MAX_BLOCK_SIZE)
    {
      break;
    }

    int r = add_transaction_to_block(block, tx, tx_index);
    assert(r == 0);
    tx_index++;
  }

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
  CC_Array *txs_to_remove;
  int r = cc_array_new(&txs_to_remove);
  assert(r == CC_OK);

  CC_ArrayIter iter;
  cc_array_iter_init(&iter, g_mempool_transactions);

  void *el;
  while (cc_array_iter_next(&iter, (void*) &el) != CC_ITER_END)
  {
    mempool_entry_t *mempool_entry = (mempool_entry_t*)el;
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
      r = cc_array_add(txs_to_remove, tx);
      assert(r == CC_OK);
    }
  }

  cc_array_iter_init(&iter, txs_to_remove);
  while (cc_array_iter_next(&iter, (void*) &el) != CC_ITER_END)
  {
    transaction_t *tx = (transaction_t*)el;
    assert(tx != NULL);

    r = remove_tx_from_mempool_nolock(tx);
    assert(r == 0);
    free_transaction(tx);
  }

  cc_array_destroy(txs_to_remove);
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
  int r = clear_expired_txs_in_mempool_noblock();
  assert(r == 0);
  return TASK_RESULT_WAIT;
}

static int compare_tx_fee(const void *a, const void *b) {
  const mempool_tx_fee_entry_t *entry_a = (const mempool_tx_fee_entry_t*)a;
  const mempool_tx_fee_entry_t *entry_b = (const mempool_tx_fee_entry_t*)b;
  
  if (entry_a->fee_per_byte > entry_b->fee_per_byte) return -1;
  if (entry_a->fee_per_byte < entry_b->fee_per_byte) return 1;
  return 0;
}

uint64_t calculate_transaction_fee(transaction_t *tx) {
  assert(tx != NULL);
  
  // Coinbase transactions don't have fees
  if (is_coinbase_tx(tx)) {
      return 0;
  }
  
  uint64_t total_input = 0;
  uint64_t total_output = 0;
  
  // Calculate total input amount
  for (uint32_t i = 0; i < tx->txin_count; i++) {
      input_transaction_t *txin = tx->txins[i];
      assert(txin != NULL);
      
      // Get the referenced output transaction
      block_t *block = get_block_from_tx_id(txin->transaction); // get the block that contains the txin previous transaction
      transaction_t *prev_tx = get_tx_by_hash_from_block(block, txin->transaction); // now get the transaction it's self
      if (prev_tx == NULL) {
          return 0; // Invalid transaction, can't calculate fee
      }
      
      // Ensure output index is valid
      if (txin->txout_index >= prev_tx->txout_count) {
          return 0; // Invalid output index
      }
      
      output_transaction_t *prev_txout = prev_tx->txouts[txin->txout_index];
      assert(prev_txout != NULL);
      
      total_input += prev_txout->amount;
  }
  
  // Calculate total output amount
  for (uint32_t i = 0; i < tx->txout_count; i++) {
      output_transaction_t *txout = tx->txouts[i];
      assert(txout != NULL);
      total_output += txout->amount;
  }
  
  // Fee is the difference between inputs and outputs
  // Return 0 if outputs exceed inputs (invalid transaction)
  return total_input > total_output ? total_input - total_output : 0;
}

int add_transactions_from_mempool(block_t *block) {
  assert(block != NULL);
  
  mtx_lock(&g_mempool_lock);
  
  // Create array to store transactions with their fees
  mempool_tx_fee_entry_t *tx_entries = malloc(sizeof(mempool_tx_fee_entry_t) * g_mempool_num_transactions);
  size_t num_entries = 0;
  
  // Calculate fees for all transactions in mempool
  CC_ArrayIter iter;
  cc_array_iter_init(&iter, g_mempool_transactions);
  
  void *el;
  while (cc_array_iter_next(&iter, (void*) &el) != CC_ITER_END) {
      mempool_entry_t *mempool_entry = (mempool_entry_t*)el;
      transaction_t *tx = mempool_entry->tx;
      
      // Skip invalid or expired transactions
      if (!valid_transaction(tx)) {
          continue;
      }
      
      uint64_t tx_size = get_tx_header_size(tx);
      uint64_t tx_fee = calculate_transaction_fee(tx);
      
      if (tx_size > 0 && tx_fee > 0) {
          tx_entries[num_entries].tx = tx;
          tx_entries[num_entries].fee_per_byte = (double)tx_fee / tx_size;
          num_entries++;
      }
  }
  
  // Sort transactions by fee per byte
  qsort(tx_entries, num_entries, sizeof(mempool_tx_fee_entry_t), compare_tx_fee);
  
  // Add transactions to block, starting with highest fee per byte
  uint32_t tx_index = 1; // Skip coinbase transaction
  uint32_t current_block_size = get_block_header_size(block);
  
  for (size_t i = 0; i < num_entries; i++) {
      transaction_t *tx = tx_entries[i].tx;
      uint32_t tx_size = get_tx_header_size(tx);
      
      // Check if adding this transaction would exceed block size limit
      if (current_block_size + tx_size >= MAX_BLOCK_SIZE) {
          continue;
      }
      
      // Add transaction to block and remove from mempool
      if (add_transaction_to_block(block, tx, tx_index) == 0) {
          remove_tx_from_mempool_nolock(tx);
          current_block_size += tx_size;
          tx_index++;
      }
  }
  
  free(tx_entries);
  mtx_unlock(&g_mempool_lock);
  return 0;
}

size_t get_mempool_size(void) {
    mtx_lock(&g_mempool_lock);
    size_t size = g_mempool_num_transactions;
    mtx_unlock(&g_mempool_lock);
    return size;
}

size_t get_mempool_bytes(void) {
    mtx_lock(&g_mempool_lock);
    size_t total_bytes = 0;
    
    CC_ArrayIter iter;
    cc_array_iter_init(&iter, g_mempool_transactions);
    
    void *el;
    while (cc_array_iter_next(&iter, (void*) &el) != CC_ITER_END) {
        mempool_entry_t *mempool_entry = (mempool_entry_t*)el;
        assert(mempool_entry != NULL);
        
        transaction_t *tx = mempool_entry->tx;
        assert(tx != NULL);
        
        // Calculate transaction size
        buffer_t *buffer = buffer_init();
        serialize_transaction(buffer, tx);
        total_bytes += buffer_get_size(buffer);
        buffer_free(buffer);
    }
    
    mtx_unlock(&g_mempool_lock);
    return total_bytes;
}

size_t get_mempool_usage(void) {
    mtx_lock(&g_mempool_lock);
    size_t total_usage = 0;
    
    // Base memory usage for mempool management structures
    total_usage += sizeof(g_mempool_transactions);
    total_usage += sizeof(mtx_t); // For g_mempool_lock
    
    CC_ArrayIter iter;
    cc_array_iter_init(&iter, g_mempool_transactions);
    
    void *el;
    while (cc_array_iter_next(&iter, (void*) &el) != CC_ITER_END) {
        mempool_entry_t *mempool_entry = (mempool_entry_t*)el;
        assert(mempool_entry != NULL);
        
        // Add mempool entry structure size
        total_usage += sizeof(mempool_entry_t);
        
        transaction_t *tx = mempool_entry->tx;
        assert(tx != NULL);
        
        // Add transaction structure size
        total_usage += sizeof(transaction_t);
        
        // Add size of transaction inputs and outputs
        total_usage += tx->txin_count * sizeof(input_transaction_t);
        total_usage += tx->txout_count * sizeof(output_transaction_t);
    }
    
    mtx_unlock(&g_mempool_lock);
    return total_usage;
}

int start_mempool(void)
{
  if (g_mempool_initialized)
  {
    return 1;
  }

  mtx_init(&g_mempool_lock, mtx_recursive);

  int r = cc_array_new(&g_mempool_transactions);
  assert(r == CC_OK);

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
  cc_array_destroy(g_mempool_transactions);

  g_mempool_num_transactions = 0;
  g_mempool_flush_task = NULL;
  g_mempool_initialized = 0;
  return 0;
}