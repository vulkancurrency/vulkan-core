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
#include <assert.h>

#include <sodium.h>

#include "common/greatest.h"
#include "common/task.h"

#include "core/blockchain.h"
#include "core/mempool.h"
#include "core/p2p.h"

static const char *g_blockchain_dir = "blockchain_tests";

SUITE_EXTERN(common_suite);
SUITE_EXTERN(crypto_suite);
SUITE_EXTERN(block_suite);
SUITE_EXTERN(blockchain_suite);
SUITE_EXTERN(transaction_suite);
SUITE_EXTERN(merkle_suite);
SUITE_EXTERN(mempool_suite);
SUITE_EXTERN(protocol_suite);

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
  if (sodium_init() == -1)
  {
    return 1;
  }

  if (init_pow())
  {
    return 1;
  }

  if (taskmgr_init())
  {
    return 1;
  }

  if (start_mempool())
  {
    return 1;
  }

  remove_blockchain(g_blockchain_dir);
  if (init_blockchain(g_blockchain_dir, 0))
  {
    return 1;
  }

  if (init_p2p())
  {
    return 1;
  }

  GREATEST_MAIN_BEGIN();

  RUN_SUITE(common_suite);
  RUN_SUITE(crypto_suite);
  RUN_SUITE(block_suite);
  RUN_SUITE(blockchain_suite);
  RUN_SUITE(transaction_suite);
  RUN_SUITE(mempool_suite);
  RUN_SUITE(merkle_suite);
  RUN_SUITE(protocol_suite);

  GREATEST_MAIN_END();

  if (close_blockchain())
  {
    return 1;
  }

  if (stop_mempool())
  {
    return 1;
  }

  if (deinit_p2p())
  {
    return 1;
  }

  if (taskmgr_shutdown())
  {
    return 1;
  }

  if (deinit_pow())
  {
    return 1;
  }

  return 0;
}
