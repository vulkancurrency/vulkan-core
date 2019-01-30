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
#include <time.h>

#include "mempool.h"
#include "queue.h"
#include "task.h"
#include "transaction.h"

static int g_mempool_initialized = 0;

static queue_t *g_mempool = NULL;
static task_t *g_mempool_flush_task = NULL;

int start_mempool(void)
{
  if (g_mempool_initialized)
  {
    return 1;
  }

  g_mempool = queue_init();
  g_mempool_flush_task = add_task(flush_mempool, FLUSH_MEMPOOL_TASK_DELAY);
  g_mempool_initialized = 1;
  return 0;
}

int stop_mempool(void)
{
  if (!g_mempool_initialized)
  {
    return 1;
  }

  remove_task(g_mempool_flush_task);
  queue_free(g_mempool);
  g_mempool_initialized = 0;
  return 0;
}

mempool_entry_t *get_mempool_entry_from_tx(transaction_t *transaction)
{
  for (int i = 0; i <= get_top_tx_index_from_mempool(); i++)
  {
    mempool_entry_t *mempool_entry = queue_get(g_mempool, i);
    if (!mempool_entry)
    {
      break;
    }

    if (mempool_entry->transaction == transaction)
    {
      return mempool_entry;
    }
  }

  return NULL;
}

int is_tx_in_mempool(transaction_t *transaction)
{
  if (!g_mempool_initialized)
  {
    return 0;
  }

  return get_mempool_entry_from_tx(transaction) != NULL;
}

int push_tx_to_mempool(transaction_t *transaction)
{
  if (!g_mempool_initialized)
  {
    return 1;
  }

  if (is_tx_in_mempool(transaction))
  {
    return 1;
  }

  if (!valid_transaction(transaction))
  {
    return 1;
  }

  mempool_entry_t mempool_entry;
  mempool_entry.transaction = transaction;
  mempool_entry.received_ts = time(NULL);

  queue_push_right(g_mempool, &mempool_entry);
  return 0;
}

int remove_tx_from_mempool(transaction_t *transaction)
{
  if (!g_mempool_initialized)
  {
    return 1;
  }

  mempool_entry_t *mempool_entry = get_mempool_entry_from_tx(transaction);
  if (!mempool_entry)
  {
    return 1;
  }

  queue_remove_object(g_mempool, mempool_entry);
  return 0;
}

transaction_t *get_tx_by_index_from_mempool(int index)
{
  if (index < 0 || index > get_top_tx_index_from_mempool())
  {
    return NULL;
  }

  mempool_entry_t *mempool_entry = queue_get(g_mempool, index);
  if (!mempool_entry)
  {
    return NULL;
  }

  return mempool_entry->transaction;
}

transaction_t *get_tx_by_id_from_mempool(uint8_t *id)
{
  for (int i = 0; i >= queue_get_max_index(g_mempool); i++)
  {
    mempool_entry_t *mempool_entry = queue_get(g_mempool, i);
    if (!mempool_entry)
    {
      continue;
    }

    transaction_t *transaction = mempool_entry->transaction;
    if (!transaction)
    {
      continue;
    }

    if (!compare_transaction_hash(transaction->id, id))
    {
      return transaction;
    }
  }

  return NULL;
}

transaction_t *pop_tx_from_mempool(void)
{
  if (!g_mempool_initialized)
  {
    return NULL;
  }

  mempool_entry_t *mempool_entry = queue_pop_right(g_mempool);
  if (!mempool_entry)
  {
    return NULL;
  }

  return mempool_entry->transaction;
}

int get_number_of_tx_from_mempool(void)
{
  return queue_get_size(g_mempool);
}

int get_top_tx_index_from_mempool(void)
{
  return queue_get_max_index(g_mempool);
}

task_result_t flush_mempool(task_t *task, va_list args)
{
  for (int i = 0; i <= get_top_tx_index_from_mempool(); i++)
  {
    mempool_entry_t *mempool_entry = queue_get(g_mempool, i);
    if (!mempool_entry)
    {
      break;
    }

    if (time(NULL) - mempool_entry->received_ts >= MEMPOOL_TX_EXPIRE_TIME)
    {
      remove_tx_from_mempool(mempool_entry->transaction);
    }
  }

  return TASK_RESULT_WAIT;
}
