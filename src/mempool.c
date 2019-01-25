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

#include "queue.h"
#include "transaction.h"

#include "mempool.h"

static int g_mempool_initialized = 0;
static queue_t *g_mempool = NULL;

int start_mempool(void)
{
  if (g_mempool_initialized)
  {
    return 1;
  }

  g_mempool = queue_init();
  g_mempool_initialized = 1;
  return 0;
}

int is_tx_in_mempool(transaction_t *transaction)
{
  if (!g_mempool_initialized)
  {
    return 0;
  }

  return queue_get_index(g_mempool, transaction) != -1;
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
    return 0;
  }

  queue_push_right(g_mempool, transaction);
  return 0;
}

int remove_tx_from_mempool(transaction_t *transaction)
{
  if (!g_mempool_initialized)
  {
    return 1;
  }

  if (!is_tx_in_mempool(transaction))
  {
    return 0;
  }

  queue_remove_object(g_mempool, transaction);
  return 0;
}

transaction_t *pop_tx_from_mempool(void)
{
  if (!g_mempool_initialized)
  {
    return NULL;
  }

  transaction_t *transaction = queue_pop_right(g_mempool);
  return transaction;
}

int get_number_of_tx_from_mempool(void)
{
  return queue_get_size(g_mempool);
}

int stop_mempool(void)
{
  if (!g_mempool_initialized)
  {
    return 1;
  }

  g_mempool_initialized = 0;
  queue_free(g_mempool);
  return 0;
}
