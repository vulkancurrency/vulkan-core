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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <inttypes.h>

#include "common/logger.h"
#include "common/util.h"

#include "blockchain.h"
#include "transaction_builder.h"
#include "transaction.h"

#include "crypto/cryptoutil.h"

#include "wallet/wallet.h"

static uint64_t get_total_entries_amount(transaction_entries_t transaction_entries)
{
  uint64_t total_amount = 0;
  for (uint16_t i = 0; i < transaction_entries.num_entries; i++)
  {
    transaction_entry_t *transaction_entry = transaction_entries.entries[i];
    assert(transaction_entry != NULL);
    total_amount += transaction_entry->amount;
  }

  return total_amount;
}

int construct_spend_tx(transaction_t **out_tx, wallet_t *wallet, int check_available_money, transaction_entries_t transaction_entries)
{
  assert(wallet != NULL);
  assert(transaction_entries.num_entries <= (uint16_t)MAX_NUM_TX_ENTRIES);

  // Check to see if the wallet has enough money to spend
  if (check_available_money)
  {
    uint64_t money_required = get_total_entries_amount(transaction_entries);
    uint64_t available_money = get_balance_for_address(wallet->address);
    if (available_money < money_required)
    {
      LOG_ERROR("Cannot make transaction, wallet has insufficient funds: %" PRIu64 "!", money_required - available_money);
      return 1;
    }
  }

  vec_void_t unspent_txs;
  vec_init(&unspent_txs);

  uint32_t num_unspent_txs = 0;
  assert(get_unspent_transactions_for_address(wallet->address, &unspent_txs, &num_unspent_txs) == 0);

  transaction_t *tx = create_new_transaction();
  uint64_t total_input = 0;

  // Collect inputs until we have enough for all outputs
  void *value = NULL;
  int index = 0;
  vec_foreach(&unspent_txs, value, index)
  {
    unspent_transaction_t *unspent_tx = (unspent_transaction_t*)value;
    assert(unspent_tx != NULL);

    for (uint32_t txout_index = 0; txout_index < unspent_tx->unspent_txout_count; txout_index++)
    {
      unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[txout_index];
      assert(unspent_txout != NULL);

      if (unspent_txout->spent == 1)
      {
        continue;
      }

      total_input += unspent_txout->amount;

      // Add the input
      input_transaction_t *txin = create_new_txin();
      memcpy(txin->transaction, unspent_tx->id, HASH_SIZE);
      txin->txout_index = txout_index;
      assert(sign_txin(txin, tx, wallet->public_key, wallet->secret_key) == 0);
      assert(add_txin_to_transaction(tx, txin, tx->txin_count) == 0);

      if (total_input >= get_total_entries_amount(transaction_entries))
      {
        break; // We have enough inputs
      }
    }

    if (total_input >= get_total_entries_amount(transaction_entries))
    {
      break; // We have enough inputs to cover all outputs
    }

    free_unspent_transaction(unspent_tx);
  }

  // Add outputs
  uint64_t total_output = 0;
  for (uint16_t i = 0; i < transaction_entries.num_entries; i++)
  {
    transaction_entry_t *transaction_entry = transaction_entries.entries[i];
    output_transaction_t *txout = create_new_txout();
    memcpy(txout->address, transaction_entry->address, ADDRESS_SIZE);
    txout->amount = transaction_entry->amount;
    total_output += txout->amount;
    assert(add_txout_to_transaction(tx, txout, tx->txout_count) == 0);
  }

  // Handle Change
  if (total_input > total_output)
  {
    uint64_t change = total_input - total_output;
    output_transaction_t *change_txout = create_new_txout();
    memcpy(change_txout->address, wallet->address, ADDRESS_SIZE);
    change_txout->amount = change;
    assert(add_txout_to_transaction(tx, change_txout, tx->txout_count) == 0);
  }

  vec_deinit(&unspent_txs);
  compute_self_tx_id(tx);
  *out_tx = tx;
  return 0;
}

int construct_coinbase_tx(transaction_t **out_tx, wallet_t *wallet, uint64_t block_reward)
{
  assert(wallet != NULL);
  transaction_t *tx = create_new_transaction();

  // construct the txout
  output_transaction_t *txout = create_new_txout();
  memcpy(txout->address, wallet->address, ADDRESS_SIZE);
  txout->amount = block_reward;
  assert(add_txout_to_transaction(tx, txout, 0) == 0);

  compute_self_tx_id(tx);
  *out_tx = tx;
  return 0;
}
