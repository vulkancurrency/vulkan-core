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
#include <assert.h>

#include <sodium.h>

#include "common/logger.h"
#include "common/task.h"
#include "common/tinycthread.h"
#include "common/util.h"

#include "core/block.h"
#include "core/blockchain.h"
#include "core/difficulty.h"
#include "core/mempool.h"
#include "core/protocol.h"
#include "core/transaction_builder.h"

#include "miner.h"

#include "wallet/wallet.h"

static int g_miner_is_mining = 0;
static wallet_t *g_current_wallet = NULL;
static task_t *g_miner_worker_status_task = NULL;

static mtx_t g_miner_lock;
static miner_worker_t *g_miner_workers[MAX_NUM_WORKER_THREADS];
static uint16_t g_num_worker_threads = 0;

void set_num_worker_threads(uint16_t num_worker_threads)
{
  assert(num_worker_threads <= (uint16_t)MAX_NUM_WORKER_THREADS);
  g_num_worker_threads = num_worker_threads;
}

uint16_t get_num_worker_threads(void)
{
  return g_num_worker_threads;
}

void set_current_wallet(wallet_t *current_wallet)
{
  g_current_wallet = current_wallet;
}

wallet_t* get_current_wallet(void)
{
  return g_current_wallet;
}

miner_worker_t* init_worker(void)
{
  miner_worker_t *worker = malloc(sizeof(miner_worker_t));
  worker->id = 0;
  worker->last_timestamp = get_current_time();
  worker->last_hashrate = 0;
  return worker;
}

int free_worker(miner_worker_t *worker)
{
  assert(worker != NULL);
  worker->id = 0;
  worker->last_timestamp = 0;
  worker->last_hashrate = 0;
  free(worker);
  return 0;
}

static void update_worker_hashrate(miner_worker_t *worker)
{
  assert(worker != NULL);
  uint32_t current_timestamp = get_current_time();
  if (current_timestamp - worker->last_timestamp >= 1)
  {
    worker->last_timestamp = current_timestamp;
    worker->last_hashrate = 0;
  }

  worker->last_hashrate++;
}

block_t* construct_computable_block_nolock(miner_worker_t *worker, wallet_t *wallet, block_t *previous_block)
{
  assert(worker != NULL);
  assert(wallet != NULL);
  assert(previous_block != NULL);

  uint32_t nonce = randombytes_random();
  uint32_t current_time = get_current_time();
  uint32_t current_block_height = get_block_height();

  uint64_t cumulative_emission = previous_block->cumulative_emission;
  uint64_t block_reward = get_block_reward(current_block_height, cumulative_emission);

  block_t *block = make_block();
  memcpy(block->previous_hash, previous_block->hash, HASH_SIZE);

  block->timestamp = current_time;
  block->nonce = nonce;
  block->difficulty = get_next_block_difficulty();
  block->cumulative_difficulty = previous_block->cumulative_difficulty + block->difficulty;
  block->cumulative_emission = cumulative_emission + block_reward;

  transaction_t *tx = make_generation_tx(wallet, block_reward);
  assert(tx != NULL);
  assert(add_transaction_to_block(block, tx, 0) == 0);
  assert(fill_block_with_txs_from_mempool(block) == 0);

  compute_self_merkle_root(block);
  compute_self_block_hash(block);
  return block;
}

block_t* construct_computable_block(miner_worker_t *worker, wallet_t *wallet, block_t *previous_block)
{
  mtx_lock(&g_miner_lock);
  block_t *block = construct_computable_block_nolock(worker, wallet, previous_block);
  mtx_unlock(&g_miner_lock);
  return block;
}

block_t* compute_next_block(miner_worker_t *worker, wallet_t *wallet, block_t *previous_block)
{
  assert(worker != NULL);
  assert(wallet != NULL);
  assert(previous_block != NULL);

  block_t *block = construct_computable_block(worker, wallet, previous_block);
  assert(block != NULL);

  while (valid_block_hash(block) == 0)
  {
    block->nonce++;
    compute_self_block_hash(block);
    update_worker_hashrate(worker);
  }

  return block;
}

static int worker_mining_thread(void *arg)
{
  miner_worker_t *worker = (miner_worker_t*)arg;
  assert(worker != NULL);

  block_t *previous_block = NULL;
  block_t *block = NULL;

  while (g_miner_is_mining)
  {
    previous_block = get_current_block();
    block = compute_next_block(worker, g_current_wallet, previous_block);
    if (validate_and_insert_block(block) == 0)
    {
      LOG_INFO("Worker: %hu found block at height: %u!", worker->id, get_block_height());
      print_block(block);
    }

    free_block(previous_block);
    free_block(block);
  }

  return 0;
}

task_result_t report_worker_mining_status(task_t *task, va_list args)
{
  for (int i = 0; i < g_num_worker_threads; i++)
  {
    miner_worker_t *worker = g_miner_workers[i];
    assert(worker != NULL);
    LOG_INFO("Worker: %u running %u h/s.", worker->id, worker->last_hashrate);
  }

  return TASK_RESULT_WAIT;
}

int start_mining(void)
{
  assert(g_current_wallet != NULL);
  if (g_miner_is_mining)
  {
    return 1;
  }

  mtx_init(&g_miner_lock, mtx_recursive);

  g_miner_is_mining = 1;
  g_miner_worker_status_task = add_task(report_worker_mining_status, WORKER_STATUS_TASK_DELAY);

  for (uint16_t i = 0; i < g_num_worker_threads; i++)
  {
    miner_worker_t *worker = init_worker();
    worker->id = i;
    if (thrd_create(&worker->thread, worker_mining_thread, worker) != thrd_success)
    {
      LOG_ERROR("Failed to start mining thread: %hu!", i);
      return 1;
    }

    g_miner_workers[i] = worker;
  }

  LOG_INFO("Started mining on %hu threads...", g_num_worker_threads);
  return 0;
}

int stop_mining(void)
{
  if (g_miner_is_mining == 0)
  {
    return 1;
  }

  remove_task(g_miner_worker_status_task);
  mtx_destroy(&g_miner_lock);

  for (int i = 0; i < g_num_worker_threads; i++)
  {
    miner_worker_t *worker = g_miner_workers[i];
    assert(worker != NULL);
    free_worker(worker);
  }

  g_miner_is_mining = 0;
  g_current_wallet = NULL;
  g_miner_worker_status_task = NULL;
  g_num_worker_threads = 0;
  return 0;
}
