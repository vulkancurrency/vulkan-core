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

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "block.h"
#include "chain.h"
#include "protocol.h"
#include "wallet.h"

#include "miner.h"

static int g_miner_is_mining = 0;

int start_mining(void)
{
  if (g_miner_is_mining)
  {
    return 1;
  }
  g_miner_is_mining = 1;
  printf("Started mining...\n");

  while (g_miner_is_mining)
  {
    uint8_t *previous_hash = get_current_block_hash();
    block_t *block = compute_next_block(previous_hash);
    insert_block_into_blockchain(block);
    uint32_t block_height = get_block_height();

    printf("Inserted block #%d\n", block_height);
    print_block(block);

    set_current_block_hash(block->hash);
    handle_broadcast_incoming_block(block);

    free(block);
  }

  return 0;
}

void stop_mining(void)
{
  if (!g_miner_is_mining)
  {
    return;
  }
  g_miner_is_mining = 0;
}

block_t *compute_next_block(uint8_t *prev_block_hash)
{
  uint32_t nonce = 0;
  time_t current_time = time(NULL);

  input_transaction_t *txin = malloc(sizeof(input_transaction_t));
  output_transaction_t *txout = malloc(sizeof(output_transaction_t));

  memset(txin->transaction, 0, 32);
  txin->txout_index = get_block_height();
  txout->amount = 50 * COIN;

  PWallet *wallet = get_wallet();
  memcpy(txout->address, wallet->address.data, ADDRESS_SIZE);
  pwallet__free_unpacked(wallet, NULL);

  transaction_t *tx = malloc(sizeof(transaction_t));
  tx->txout_count = 1;
  tx->txouts = malloc(sizeof(output_transaction_t *) * 1);
  tx->txouts[0] = txout;

  sign_txin(txin, tx, wallet->public_key.data, wallet->secret_key.data);

  tx->txin_count = 1;
  tx->txins = malloc(sizeof(input_transaction_t *) * 1);
  tx->txins[0] = txin;
  compute_self_tx_id(tx);

  block_t *block = make_block();
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t *) * 1);
  block->transactions[0] = tx;
  block->timestamp = current_time;
  memcpy(block->previous_hash, get_current_block_hash(), 32);

  compute_self_merkle_root(block);
  hash_block(block);

  while (!valid_block_hash(block))
  {
    block->nonce = nonce;

    hash_block(block);
    nonce++;
  }

  return block;
}
