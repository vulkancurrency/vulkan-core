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

#include "block.h"
#include "transaction.h"
#include "genesis.h"

block_t *get_genesis_block(void)
{
  // construct the new genesis block and copy all of the contents
  // from the genesis block template to the new genesis block
  if (testnet_genesis_block == NULL)
  {
    testnet_genesis_block = make_block();
    assert(copy_block(&testnet_genesis_block_template, testnet_genesis_block) == 0);

    // add the tx
    transaction_t *tx = &testnet_genesis_tx;
    assert(tx != NULL);

    transaction_t *generation_tx = make_transaction();
    assert(copy_transaction(tx, generation_tx) == 0);

    assert(add_transaction_to_block(testnet_genesis_block, generation_tx, 0) == 0);

    // add txins
    for (uint32_t txin_index = 0; txin_index < NUM_TESTNET_GENESIS_TXINS; txin_index++)
    {
      input_transaction_t *txin = &testnet_genesis_input_txs[txin_index];
      assert(txin != NULL);

      input_transaction_t *generation_txin = make_txin();
      assert(copy_txin(txin, generation_txin) == 0);

      assert(add_txin_to_transaction(generation_tx, generation_txin, txin_index) == 0);
    }

    // add txouts
    for (uint32_t txout_index = 0; txout_index < NUM_TESTNET_GENESIS_TXINS; txout_index++)
    {
      output_transaction_t *txout = &testnet_genesis_output_txs[txout_index];
      assert(txout != NULL);

      output_transaction_t *generation_txout = make_txout();
      assert(copy_txout(txout, generation_txout) == 0);

      assert(add_txout_to_transaction(generation_tx, generation_txout, txout_index) == 0);
    }
  }

  return parameters_get_use_testnet() ? testnet_genesis_block : &mainnet_genesis_block;
}
