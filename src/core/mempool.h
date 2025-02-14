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

#pragma once

#include <stdint.h>
#include <time.h>

#include "common/task.h"
#include "common/vulkan.h"

#include "block.h"
#include "parameters.h"
#include "transaction.h"

VULKAN_BEGIN_DECL

#define FLUSH_MEMPOOL_TASK_DELAY 60

typedef struct MempoolEntry
{
  transaction_t *tx;
  uint32_t received_ts;
} mempool_entry_t;

typedef struct MempoolFeeEntry {
  transaction_t *tx;
  double fee_per_byte;
} mempool_tx_fee_entry_t;

VULKAN_API mempool_entry_t* init_mempool_entry(void);
VULKAN_API void free_mempool_entry(mempool_entry_t *mempool_entry);

VULKAN_API mempool_entry_t* get_mempool_entry_from_mempool(uint8_t *tx_hash);
VULKAN_API transaction_t* get_tx_from_mempool(uint8_t *tx_hash);

VULKAN_API int is_tx_in_mempool_nolock(transaction_t *tx);
VULKAN_API int is_tx_in_mempool(transaction_t *tx);

VULKAN_API int add_tx_to_mempool_nolock(transaction_t *tx);
VULKAN_API int add_tx_to_mempool(transaction_t *tx);

VULKAN_API int validate_and_add_tx_to_mempool_nolock(transaction_t *tx);
VULKAN_API int validate_and_add_tx_to_mempool(transaction_t *tx);

VULKAN_API int remove_tx_from_mempool_nolock(transaction_t *tx);
VULKAN_API int remove_tx_from_mempool(transaction_t *tx);

VULKAN_API transaction_t* pop_tx_from_mempool_nolock(void);
VULKAN_API transaction_t* pop_tx_from_mempool(void);

VULKAN_API uint64_t get_num_txs_in_mempool(void);

VULKAN_API int fill_block_with_txs_from_mempool_nolock(block_t *block);
VULKAN_API int fill_block_with_txs_from_mempool(block_t *block);

VULKAN_API int clear_txs_in_mempool_from_block_nolock(block_t *block);
VULKAN_API int clear_txs_in_mempool_from_block(block_t *block);

VULKAN_API int clear_expired_txs_in_mempool_nolock(void);
VULKAN_API int clear_expired_txs_in_mempool_noblock(void);
VULKAN_API int clear_expired_txs_in_mempool(void);

VULKAN_API static int compare_tx_fee(const void *a, const void *b);
VULKAN_API uint64_t calculate_transaction_fee(transaction_t *tx);
VULKAN_API int add_transactions_from_mempool(block_t *block);

VULKAN_API int start_mempool(void);
VULKAN_API int stop_mempool(void);

VULKAN_END_DECL