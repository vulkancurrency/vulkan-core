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
#include <time.h>
#include <string.h>
#include "assert.h"

#include "common/tinycthread.h"
#include "common/util.h"

#include "core/block.h"
#include "core/blockchain.h"
#include "core/difficulty.h"
#include "core/protocol.h"

#include "miner.h"

#include "wallet/wallet.h"

static int g_miner_is_mining = 0;
static wallet_t *g_current_wallet = NULL;

static thrd_t g_worker_threads[MAX_NUM_WORKER_THREADS];
static mtx_t g_worker_lock;
static size_t g_num_worker_threads = 0;

void set_num_worker_threads(size_t num_worker_threads)
{
  assert(num_worker_threads <= MAX_NUM_WORKER_THREADS);
  g_num_worker_threads = num_worker_threads;
}

size_t get_num_worker_threads(void)
{
  return g_num_worker_threads;
}

void set_current_wallet(wallet_t *current_wallet)
{
  g_current_wallet = current_wallet;
}

wallet_t *get_current_wallet(void)
{
  return g_current_wallet;
}

block_t *compute_next_block(wallet_t *wallet, block_t *previous_block)
{
  uint32_t nonce = (uint32_t)RANDOM_RANGE(0, UINT32_MAX);
  uint32_t current_time = get_current_time();
  uint32_t current_block_height = get_block_height();

  uint64_t already_generated_coins = previous_block->already_generated_coins;
  uint64_t block_reward = get_block_reward(current_block_height, already_generated_coins);

  block_t *block = make_block();
  memcpy(block->previous_hash, previous_block->hash, HASH_SIZE);

  block->timestamp = current_time;
  block->nonce = nonce;
  block->difficulty = get_next_block_difficulty();
  block->cumulative_difficulty = previous_block->cumulative_difficulty + block->difficulty;
  block->already_generated_coins = already_generated_coins + block_reward;

  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t) * block->transaction_count);

  transaction_t *tx = make_generation_tx(wallet, current_block_height, already_generated_coins, block_reward);
  block->transactions[0] = tx;

  compute_self_merkle_root(block);
  hash_block(block);

  while (!valid_block_hash(block))
  {
    nonce++;
    block->nonce = nonce;
    hash_block(block);
  }

  return block;
}

static int worker_mining_thread(void *arg)
{
  size_t worker_index = (size_t)arg;

  uint32_t current_block_height = 0;
  block_t *previous_block = NULL;
  block_t *block = NULL;

  while (g_miner_is_mining)
  {
    current_block_height = get_block_height();
    previous_block = get_current_block();
    block = compute_next_block(g_current_wallet, previous_block);

    // see if we got lucky and found a block, attempt to insert the block
    // into the blockchain before the other workers...
    mtx_lock(&g_worker_lock);
    if (validate_and_insert_block(block))
    {
      printf("Worker: %zu inserted block at height %d!\n", worker_index, current_block_height);
      print_block(block);
      handle_packet_broadcast(PKT_TYPE_INCOMING_BLOCK, block);
    }

    mtx_unlock(&g_worker_lock);

    free_block(previous_block);
    free_block(block);

    // yield thread to give other threads a chance to
    // find a block and submit it...
    thrd_yield();
  }

  return 0;
}

int start_mining()
{
  assert(g_current_wallet != NULL);
  if (g_miner_is_mining)
  {
    return 1;
  }

  mtx_init(&g_worker_lock, mtx_plain);
  g_miner_is_mining = 1;

  for (size_t i = 0; i <= g_num_worker_threads; i++)
  {
    thrd_t t = g_worker_threads[i];
    if (thrd_create(&t, worker_mining_thread, (void*)i) != thrd_success)
    {
      fprintf(stderr, "Failed to start mining thread: %zu!\n", i);
      return 1;
    }
  }

  printf("Started mining on %zu threads...\n", g_num_worker_threads);
  return 0;
}

void stop_mining(void)
{
  if (!g_miner_is_mining)
  {
    return;
  }

  mtx_destroy(&g_worker_lock);

  g_current_wallet = NULL;
  g_miner_is_mining = 0;
}
