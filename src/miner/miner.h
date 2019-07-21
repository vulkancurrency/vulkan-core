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

#include <stdlib.h>
#include <stdint.h>

#include "common/task.h"
#include "common/util.h"
#include "common/vulkan.h"

#include "core/block.h"

#include "wallet/wallet.h"

VULKAN_BEGIN_DECL

#define MAX_NUM_WORKER_THREADS 1024
#define WORKER_STATUS_TASK_DELAY 10

typedef struct MinerWorker
{
  thrd_t thread;
  uint16_t id;
  int running;

  uint32_t last_timestamp;
  uint32_t last_hashrate;
} miner_worker_t;

VULKAN_API int get_is_miner_initialized(void);

VULKAN_API void set_num_worker_threads(uint16_t num_worker_threads);
VULKAN_API uint16_t get_num_worker_threads(void);

VULKAN_API void set_current_wallet(wallet_t *current_wallet);
VULKAN_API wallet_t* get_current_wallet(void);

VULKAN_API void set_workers_paused(int workers_paused);
VULKAN_API int get_workers_paused(void);

VULKAN_API void set_miner_generate_genesis(int generate_genesis);
VULKAN_API int get_miner_generate_genesis(void);

VULKAN_API miner_worker_t* init_worker(void);
VULKAN_API void free_worker(miner_worker_t *worker);

VULKAN_API block_t* construct_computable_block(miner_worker_t *worker, wallet_t *wallet, block_t *previous_block);
VULKAN_API block_t* construct_computable_genesis_block(wallet_t *wallet);
VULKAN_API int compute_block(miner_worker_t *worker, block_t *block);

VULKAN_API void killall_threads(void);
VULKAN_API void wait_for_threads_to_stop(void);

VULKAN_API int start_mining(void);
VULKAN_API int stop_mining(void);

VULKAN_END_DECL
