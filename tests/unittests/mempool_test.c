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

#include "common/greatest.h"

#include "common/task.h"

#include "core/mempool.h"
#include "core/transaction.h"

SUITE(mempool_suite);

TEST can_add_to_mempool(void)
{
  uint8_t transaction[32] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };

  uint8_t address[32] = {
    0x01, 0x3e, 0x46, 0xa5,
    0xc6, 0x99, 0x4e, 0x35,
    0x55, 0x50, 0x1c, 0xba,
    0xc0, 0x7c, 0x06, 0x77
  };

  input_transaction_t *txin = malloc(sizeof(input_transaction_t));
  output_transaction_t *txout = malloc(sizeof(output_transaction_t));

  txin->txout_index = 0;
  txout->amount = 50;
  memcpy(txin->transaction, transaction, 32);
  memcpy(txout->address, address, 32);

  transaction_t *tx = malloc(sizeof(transaction_t));
  tx->txout_count = 1;
  tx->txouts = malloc(sizeof(output_transaction_t *) * tx->txout_count);
  tx->txouts[0] = txout;

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  sign_txin(txin, tx, pk, sk);

  tx->txin_count = 1;
  tx->txins = malloc(sizeof(input_transaction_t *) * tx->txin_count);
  tx->txins[0] = txin;

  taskmgr_init();
  start_mempool();

  ASSERT_EQ(get_number_of_tx_from_mempool(), 0);
  push_tx_to_mempool(tx);
  ASSERT_EQ(get_number_of_tx_from_mempool(), 1);
  transaction_t *mempool_tx = pop_tx_from_mempool();
  ASSERT(mempool_tx != NULL);
  ASSERT_EQ(get_number_of_tx_from_mempool(), 0);

  ASSERT_MEM_EQ(mempool_tx->txouts[0]->address, txout->address, 32);

  stop_mempool();
  taskmgr_shutdown();

  PASS();
}

GREATEST_SUITE(mempool_suite)
{
  RUN_TEST(can_add_to_mempool);
}
