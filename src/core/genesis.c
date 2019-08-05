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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "common/util.h"
#include "common/vulkan.h"

#include "block.h"
#include "transaction.h"
#include "genesis.h"

#include "crypto/cryptoutil.h"

static block_t *g_testnet_genesis_block = NULL;
static block_t *g_mainnet_genesis_block = NULL;

static int copy_genesis_block_template(const block_genesis_entry_t block_template,
  const transaction_genesis_entry_t tx_template, size_t num_txouts,
  const output_transaction_genesis_entry_t output_txs_template[],
  block_t **block_out)
{
  block_t *block = make_block();
  block->version = block_template.version;

  size_t out_size = 0;
  uint8_t *previous_hash = hex2bin(block_template.previous_hash_str, &out_size);
  assert(out_size == HASH_SIZE);
  memcpy(block->previous_hash, previous_hash, HASH_SIZE);
  free(previous_hash);

  uint8_t *hash = hex2bin(block_template.hash_str, &out_size);
  assert(out_size == HASH_SIZE);
  memcpy(block->hash, hash, HASH_SIZE);
  free(hash);

  block->timestamp = block_template.timestamp;
  block->nonce = block_template.nonce;
  block->bits = block_template.bits;
  block->cumulative_emission = block_template.cumulative_emission;

  uint8_t *merkle_root = hex2bin(block_template.merkle_root_str, &out_size);
  assert(out_size == HASH_SIZE);
  memcpy(block->merkle_root, merkle_root, HASH_SIZE);
  free(merkle_root);

  // add the tx
  transaction_t *generation_tx = make_transaction();
  uint8_t *id = hex2bin(tx_template.id_str, &out_size);
  assert(out_size == HASH_SIZE);
  memcpy(generation_tx->id, id, HASH_SIZE);
  free(id);

  if (add_transaction_to_block(block, generation_tx, 0))
  {
    return 1;
  }

  // add txouts
  for (uint32_t txout_index = 0; txout_index < num_txouts; txout_index++)
  {
    const output_transaction_genesis_entry_t *txout_genesis_entry = &output_txs_template[txout_index];
    assert(txout_genesis_entry != NULL);

    output_transaction_t *generation_txout = make_txout();

    generation_txout->amount = txout_genesis_entry->amount;

    uint8_t *address = hex2bin(txout_genesis_entry->address_str, &out_size);
    assert(out_size == ADDRESS_SIZE);
    memcpy(generation_txout->address, address, ADDRESS_SIZE);
    free(address);

    if (add_txout_to_transaction(generation_tx, generation_txout, txout_index))
    {
      return 1;
    }
  }

  *block_out = block;
  return 0;
}

block_t *get_genesis_block(void)
{
  // construct the new genesis block and copy all of the contents
  // from the genesis block template to the new genesis block
  if (g_testnet_genesis_block == NULL)
  {
    int result = copy_genesis_block_template(testnet_genesis_block_template, testnet_genesis_tx,
      NUM_TESTNET_GENESIS_TXOUTS, testnet_genesis_output_txs, &g_testnet_genesis_block);

    ASSERT_WITH_MESS(result == 0, "Failed to copy testnet genesis block template!");
  }

  if (g_mainnet_genesis_block == NULL)
  {
    int result = copy_genesis_block_template(mainnet_genesis_block_template, mainnet_genesis_tx,
      NUM_MAINNET_GENESIS_TXOUTS, mainnet_genesis_output_txs, &g_mainnet_genesis_block);

    ASSERT_WITH_MESS(result == 0, "Failed to copy mainnet genesis block template!");
  }

  return parameters_get_use_testnet() ? g_testnet_genesis_block : g_mainnet_genesis_block;
}
