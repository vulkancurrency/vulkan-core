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

#include "transaction.h"
#include "mempool.h"

static int g_mempool_initialized = 0;
static mempool_t *g_mempool = NULL;

int start_mempool()
{
  if (g_mempool_initialized)
  {
    return 1;
  }
  else
  {
    g_mempool = malloc(sizeof(mempool_t));
    g_mempool->size = 0;
    g_mempool->transactions = malloc(sizeof(transaction_t *));
    g_mempool_initialized = 1;
    return 0;
  }
}

int push_tx_to_mempool(transaction_t *tx)
{
  if (g_mempool_initialized != 1)
  {
    return 1;
  }

  g_mempool->size++;
  realloc(g_mempool->transactions, sizeof(transaction_t *) * g_mempool->size);
  g_mempool->transactions[g_mempool->size - 1] = tx;
  return 0;
}

transaction_t *pop_tx_from_mempool()
{
  if (g_mempool_initialized != 1)
  {
    return NULL;
  }

  transaction_t *tx = g_mempool->transactions[g_mempool->size - 1];
  g_mempool->size--;
  realloc(g_mempool->transactions, sizeof(transaction_t *) * g_mempool->size);
  return tx;
}

int get_number_of_tx_from_mempool()
{
  return g_mempool->size;
}

int stop_mempool()
{
  if (g_mempool_initialized)
  {
    free(g_mempool);
    g_mempool_initialized = 0;
    return 0;
  }

  return 1;
}
