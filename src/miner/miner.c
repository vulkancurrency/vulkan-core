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
#include "core/mempool.h"
#include "core/net.h"
#include "core/protocol.h"
#include "core/transaction_builder.h"

#include "miner.h"

#include "wallet/wallet.h"

static int g_miner_initialized = 0;
static wallet_t *g_current_wallet = NULL;
static task_t *g_miner_worker_status_task = NULL;

static mtx_t g_miner_lock;
static miner_worker_t *g_miner_workers[MAX_NUM_WORKER_THREADS];
static uint16_t g_num_worker_threads = 1;
static int g_miner_workers_paused = 0;
static int g_miner_generate_genesis = 0;

int get_is_miner_initialized(void)
{
  return g_miner_initialized;
}

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

void set_workers_paused(int workers_paused)
{
  g_miner_workers_paused = workers_paused;
}

int get_workers_paused(void)
{
  return g_miner_workers_paused;
}

void set_miner_generate_genesis(int generate_genesis)
{
  g_miner_generate_genesis = generate_genesis;
}

int get_miner_generate_genesis(void)
{
  return g_miner_generate_genesis;
}

miner_worker_t* init_worker(void)
{
  miner_worker_t *worker = malloc(sizeof(miner_worker_t));
  assert(worker != NULL);
  worker->id = 0;
  worker->running = 0;
  worker->last_timestamp = get_current_time();
  worker->last_hashrate = 0;
  return worker;
}

void free_worker(miner_worker_t *worker)
{
  assert(worker != NULL);
  worker->id = 0;
  worker->running = 0;
  worker->last_timestamp = 0;
  worker->last_hashrate = 0;
  free(worker);
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

block_t* construct_computable_block(miner_worker_t *worker, wallet_t *wallet, block_t *previous_block)
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
  block->bits = get_next_work_required(previous_block->hash);
  block->cumulative_emission = cumulative_emission + block_reward;

  transaction_t *tx = NULL;
  assert(construct_coinbase_tx(&tx, wallet, block_reward) == 0);
  assert(tx != NULL);

  assert(add_transaction_to_block(block, tx, 0) == 0);
  assert(fill_block_with_txs_from_mempool(block) == 0);

  assert(compute_self_merkle_root(block) == 0);
  assert(compute_self_block_hash(block) == 0);
  return block;
}

block_t* construct_computable_genesis_block(wallet_t *wallet)
{
  assert(wallet != NULL);

  block_t *genesis_block = make_block();
  genesis_block->timestamp = parameters_get_genesis_timestamp();
  genesis_block->nonce = randombytes_random();
  genesis_block->bits = get_next_work_required(NULL);

  uint64_t block_reward = get_block_reward(0, 0);
  genesis_block->cumulative_emission = block_reward;

  // add genesis transactions
  transaction_t *tx = NULL;
  assert(construct_coinbase_tx(&tx, wallet, block_reward) == 0);
  assert(tx != NULL);
  assert(add_transaction_to_block(genesis_block, tx, 0) == 0);

  assert(compute_self_merkle_root(genesis_block) == 0);
  assert(compute_self_block_hash(genesis_block) == 0);
  return genesis_block;
}

int compute_block(miner_worker_t *worker, block_t *block)
{
  assert(block != NULL);
  while (valid_block_hash(block) == 0)
  {
    block->nonce++;
    if (compute_self_block_hash(block))
    {
      return 1;
    }

    if (worker != NULL)
    {
      update_worker_hashrate(worker);
    }
  }

  return 0;
}

static int worker_mining_thread(void *arg)
{
  assert(arg != NULL);
  miner_worker_t *worker = (miner_worker_t*)arg;
  assert(worker != NULL);

  if (g_miner_generate_genesis)
  {
    block_t *genesis_block = construct_computable_genesis_block(g_current_wallet);
    assert(genesis_block != NULL);

    if (compute_block(NULL, genesis_block))
    {
      char *block_hash_str = bin2hex(genesis_block->hash, HASH_SIZE);
      LOG_ERROR("Failed to compute newly constructed genesis block: %s", block_hash_str);
      free(block_hash_str);
      free_block(genesis_block);
      goto worker_thread_fail;
    }

    char *block_hash_str = bin2hex(genesis_block->hash, HASH_SIZE);
    LOG_INFO("Found genesis block: %s", block_hash_str);
    free(block_hash_str);

    printf("\n");
    print_block(genesis_block);
    print_block_transactions(genesis_block);
    free_block(genesis_block);

    // we're done, force the process to close
    killall_threads();
    exit(0);
  }

  block_t *previous_block = NULL;
  block_t *block = NULL;

  while (g_miner_initialized)
  {
    if (g_miner_workers_paused)
    {
      sleep(1);
      continue;
    }

    previous_block = get_current_block();
    assert(previous_block != NULL);

    block_t *block = construct_computable_block(worker, g_current_wallet, previous_block);
    assert(block != NULL);

    if (compute_block(worker, block))
    {
      char *block_hash_str = bin2hex(block->hash, HASH_SIZE);
      LOG_ERROR("Failed to compute newly constructed block: %s", block_hash_str);
      free(block_hash_str);
      goto worker_thread_fail;
    }

    if (validate_and_insert_block(block) == 0)
    {
      LOG_INFO("Worker[%hu]: found block at height: %u!", worker->id, get_block_height());
      print_block(block);
    }

    free_block(previous_block);
    free_block(block);
  }

  return 0;

worker_thread_fail:
  killall_threads();
  return 1;
}

static task_result_t report_worker_mining_status(task_t *task, va_list args)
{
  for (int i = 0; i < g_num_worker_threads; i++)
  {
    miner_worker_t *worker = g_miner_workers[i];
    assert(worker != NULL);

    if (g_miner_workers_paused)
    {
      LOG_INFO("Worker[%u]: miner thread paused, waiting for resume...", worker->id);
    }
    else
    {
      LOG_INFO("Worker[%u]: miner thread running with %u h/s", worker->id, worker->last_hashrate);
    }
  }

  return TASK_RESULT_WAIT;
}

void killall_threads(void)
{
  for (int i = 0; i < g_num_worker_threads; i++)
  {
    miner_worker_t *worker = g_miner_workers[i];
    assert(worker != NULL);

    worker->running = 0;
  }
}

void wait_for_threads_to_stop(void)
{
  while (g_miner_initialized)
  {
    sleep(1);
    for (int i = 0; i < g_num_worker_threads; i++)
    {
      miner_worker_t *worker = g_miner_workers[i];
      assert(worker != NULL);

      if (worker->running)
      {
        continue;
      }
    }
  }
}

int start_mining(void)
{
  assert(g_current_wallet != NULL);
  if (g_miner_initialized)
  {
    return 1;
  }

  mtx_init(&g_miner_lock, mtx_recursive);

  g_miner_initialized = 1;
  g_miner_worker_status_task = add_task(report_worker_mining_status, WORKER_STATUS_TASK_DELAY);

  if (g_miner_generate_genesis)
  {
    LOG_INFO("Creating new genesis block, this make take a while...");
  }

  for (uint16_t i = 0; i < g_num_worker_threads; i++)
  {
    miner_worker_t *worker = init_worker();
    worker->id = i;
    worker->running = 1;
    if (thrd_create(&worker->thread, worker_mining_thread, worker) != thrd_success)
    {
      LOG_ERROR("Failed to start mining thread: %hu!", i);
      return 1;
    }

    g_miner_workers[i] = worker;
  }

  LOG_INFO("Started mining on %hu threads...", g_num_worker_threads);
  if (g_miner_generate_genesis)
  {
    // since we are trying to mine the genesis block, wait until
    // all of the worker threads stop before releasing the main thread...
    wait_for_threads_to_stop();
  }

  return 0;
}

int stop_mining(void)
{
  if (g_miner_initialized == 0)
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

  g_miner_initialized = 0;
  g_current_wallet = NULL;
  g_miner_worker_status_task = NULL;
  g_num_worker_threads = 0;
  return 0;
}
