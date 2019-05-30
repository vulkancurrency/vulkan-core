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

#pragma once

#include <stdint.h>

#include "core/block.h"

#include "wallet/wallet.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_NUM_WORKER_THREADS 1024
#define WORKER_STATUS_TASK_DELAY 10

typedef struct MinerWorker
{
  uint16_t id;
  thrd_t thread;
  uint32_t last_timestamp;
  uint32_t last_hashrate;
} miner_worker_t;

int get_is_miner_initialized(void);

void set_num_worker_threads(uint16_t num_worker_threads);
uint16_t get_num_worker_threads(void);

void set_current_wallet(wallet_t *current_wallet);
wallet_t* get_current_wallet(void);

void set_workers_paused(int workers_paused);
int get_workers_paused(void);

miner_worker_t* init_worker(void);
void free_worker(miner_worker_t *worker);

block_t* construct_computable_block_nolock(miner_worker_t *worker, wallet_t *wallet, block_t *previous_block);
block_t* construct_computable_block(miner_worker_t *worker, wallet_t *wallet, block_t *previous_block);

block_t* compute_next_block(miner_worker_t *worker, wallet_t *wallet, block_t *previous_block);
task_result_t report_worker_mining_status(task_t *task, va_list args);

int start_mining(void);
int stop_mining(void);

#ifdef __cplusplus
}
#endif
