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
#include <stdint.h>
#include <assert.h>

#include "common/logger.h"
#include "common/util.h"

#include "blockchain.h"
#include "transaction_builder.h"
#include "transaction.h"

#include "wallet/wallet.h"

input_transaction_t* make_txin(uint32_t txout_index)
{
  input_transaction_t *txin = malloc(sizeof(input_transaction_t));
  memset(txin->transaction, 0, HASH_SIZE);
  txin->txout_index = txout_index;
  return txin;
}

output_transaction_t* make_txout(uint8_t *address, uint64_t amount)
{
  output_transaction_t *txout = malloc(sizeof(output_transaction_t));
  txout->amount = amount;
  memcpy(txout->address, address, ADDRESS_SIZE);
  return txout;
}

transaction_t* make_tx(wallet_t *wallet, transaction_entries_t transaction_entries)
{
  assert(wallet != NULL);
  assert(transaction_entries.num_entries <= (uint16_t)MAX_NUM_TX_ENTRIES);

  transaction_t *tx = malloc(sizeof(transaction_t));

  tx->txin_count = transaction_entries.num_entries;
  tx->txins = malloc(sizeof(input_transaction_t) * tx->txin_count);

  tx->txout_count = transaction_entries.num_entries;
  tx->txouts = malloc(sizeof(output_transaction_t) * tx->txout_count);

  for (uint16_t i = 0; i < transaction_entries.num_entries; i++)
  {
    transaction_entry_t transaction_entry = transaction_entries.entries[i];

    // txout index should be the same as the txin index...
    input_transaction_t *txin = make_txin(i);
    output_transaction_t *txout = make_txout(transaction_entry.address, transaction_entry.amount);

    assert(txin != NULL);
    assert(txout != NULL);

    tx->txins[i] = txin;
    tx->txouts[i] = txout;

    assert(sign_txin(txin, tx, wallet->public_key, wallet->secret_key) == 0);
  }

  compute_self_tx_id(tx);
  return tx;
}

transaction_t* make_generation_tx(wallet_t *wallet, uint64_t block_reward)
{
  transaction_entry_t transaction_entry;
  transaction_entry.address = wallet->address;
  transaction_entry.amount = block_reward;

  transaction_entries_t transaction_entries;
  transaction_entries.num_entries = 1;
  transaction_entries.entries[0] = transaction_entry;

  return make_tx(wallet, transaction_entries);
}
