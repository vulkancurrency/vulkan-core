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

#include <sodium.h>

#include "common/util.h"

#include "transaction.h"

#include "crypto/cryptoutil.h"

#include "wallet/wallet.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct TransactionEntry
{
  uint8_t address[ADDRESS_SIZE];
  uint64_t amount;
} transaction_entry_t;

typedef struct TransactionEntries
{
  uint16_t num_entries;
  transaction_entry_t *entries[MAX_NUM_TX_ENTRIES];
} transaction_entries_t;

uint64_t get_total_entries_amount(transaction_entries_t transaction_entries);

int construct_spend_tx(transaction_t **out_tx, wallet_t *wallet, int check_available_money, transaction_entries_t transaction_entries);
int construct_generation_tx(transaction_t **out_tx, wallet_t *wallet, uint64_t block_reward);

#ifdef __cplusplus
}
#endif
