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

#include "miner.h"

#include "common/util.h"

#include "core/block.h"
#include "core/blockchain.h"
#include "core/difficulty.h"
#include "core/protocol.h"

#include "wallet/wallet.h"

static int g_miner_is_mining = 0;

int start_mining(void)
{
  if (g_miner_is_mining)
  {
    return 1;
  }
  g_miner_is_mining = 1;
  PWallet *wallet = get_wallet();
  printf("Started mining...\n");

  while (g_miner_is_mining)
  {
    block_t *previous_block = get_current_block();
    block_t *block = compute_next_block(wallet, previous_block);
    if (validate_and_insert_block(block))
    {
      printf("Inserted block #%d\n", get_block_height());
      print_block(block);
      handle_packet_broadcast(PKT_TYPE_INCOMING_BLOCK, block);
    }

    free_block(previous_block);
    free_block(block);
  }

  pwallet__free_unpacked(wallet, NULL);
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

block_t *compute_next_block(PWallet *wallet, block_t *previous_block)
{
  uint32_t nonce = 0;
  uint32_t current_time = get_current_time();
  uint32_t current_block_height = get_block_height();

  uint64_t already_generated_coins = previous_block->already_generated_coins;
  uint64_t block_reward = get_block_reward(current_block_height, already_generated_coins);

  block_t *block = make_block();
  memcpy(block->previous_hash, previous_block->hash, HASH_SIZE);

  block->timestamp = current_time;
  block->difficulty = get_next_block_difficulty();
  block->cumulative_difficulty = previous_block->cumulative_difficulty + block->difficulty;
  block->already_generated_coins = already_generated_coins + block_reward;

  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t*) * block->transaction_count);

  transaction_t *tx = make_generation_tx(wallet, current_block_height, already_generated_coins, block_reward);
  block->transactions[0] = tx;

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
