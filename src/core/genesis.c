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
#include <stdint.h>

#include "common/util.h"

#include "block.h"
#include "transaction.h"
#include "genesis.h"

#include "crypto/cryptoutil.h"

block_t *get_genesis_block(void)
{
  // construct the new genesis block and copy all of the contents
  // from the genesis block template to the new genesis block
  if (testnet_genesis_block == NULL)
  {
    testnet_genesis_block = make_block();
    testnet_genesis_block->version = testnet_genesis_block_template.version;

    size_t out_size = 0;
    uint8_t *previous_hash = hex2bin(testnet_genesis_block_template.previous_hash_str, &out_size);
    assert(out_size == HASH_SIZE);
    memcpy(testnet_genesis_block->previous_hash, previous_hash, HASH_SIZE);
    free(previous_hash);

    uint8_t *hash = hex2bin(testnet_genesis_block_template.hash_str, &out_size);
    assert(out_size == HASH_SIZE);
    memcpy(testnet_genesis_block->hash, hash, HASH_SIZE);
    free(hash);

    testnet_genesis_block->timestamp = testnet_genesis_block_template.timestamp;
    testnet_genesis_block->nonce = testnet_genesis_block_template.nonce;
    testnet_genesis_block->bits = testnet_genesis_block_template.bits;
    testnet_genesis_block->cumulative_emission = testnet_genesis_block_template.cumulative_emission;

    uint8_t *merkle_root = hex2bin(testnet_genesis_block_template.merkle_root_str, &out_size);
    assert(out_size == HASH_SIZE);
    memcpy(testnet_genesis_block->merkle_root, merkle_root, HASH_SIZE);
    free(merkle_root);

    // add the tx
    transaction_t *generation_tx = make_transaction();
    uint8_t *id = hex2bin(testnet_genesis_tx.id_str, &out_size);
    assert(out_size == HASH_SIZE);
    memcpy(generation_tx->id, id, HASH_SIZE);
    free(id);

    assert(add_transaction_to_block(testnet_genesis_block, generation_tx, 0) == 0);

    // add txins
    for (uint32_t txin_index = 0; txin_index < NUM_TESTNET_GENESIS_TXINS; txin_index++)
    {
      input_transaction_genesis_entry_t *txin_genesis_entry = &testnet_genesis_input_txs[txin_index];
      input_transaction_t *generation_txin = make_txin();

      uint8_t *transaction = hex2bin(txin_genesis_entry->transaction_str, &out_size);
      assert(out_size == HASH_SIZE);
      memcpy(generation_txin->transaction, transaction, HASH_SIZE);
      free(transaction);

      generation_txin->txout_index = txin_genesis_entry->txout_index;

      uint8_t *signature = hex2bin(txin_genesis_entry->signature_str, &out_size);
      assert(out_size == crypto_sign_BYTES);
      memcpy(generation_txin->signature, signature, crypto_sign_BYTES);
      free(signature);

      uint8_t *public_key = hex2bin(txin_genesis_entry->public_key_str, &out_size);
      assert(out_size == crypto_sign_PUBLICKEYBYTES);
      memcpy(generation_txin->public_key, public_key, crypto_sign_PUBLICKEYBYTES);
      free(public_key);

      assert(add_txin_to_transaction(generation_tx, generation_txin, txin_index) == 0);
    }

    // add txouts
    for (uint32_t txout_index = 0; txout_index < NUM_TESTNET_GENESIS_TXINS; txout_index++)
    {
      output_transaction_genesis_entry_t *txout_genesis_entry = &testnet_genesis_output_txs[txout_index];
      output_transaction_t *generation_txout = make_txout();

      generation_txout->amount = txout_genesis_entry->amount;

      uint8_t *address = hex2bin(txout_genesis_entry->address_str, &out_size);
      assert(out_size == ADDRESS_SIZE);
      memcpy(generation_txout->address, address, ADDRESS_SIZE);
      free(address);

      assert(add_txout_to_transaction(generation_tx, generation_txout, txout_index) == 0);
    }
  }

  return parameters_get_use_testnet() ? testnet_genesis_block : &mainnet_genesis_block;
}
