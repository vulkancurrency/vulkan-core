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
#include <sodium.h>

#include "common/greatest.h"
#include "common/util.h"

#include "core/transaction.h"

#include "crypto/cryptoutil.h"

#include "wallet/wallet.h"

SUITE(transaction_suite);

TEST can_sign_txin(void)
{
  input_transaction_t txin = {
    .transaction = {
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
    },
    .txout_index = 0
  };

  output_transaction_t txout = {
    .amount = 50,
    .address = {
      0x01, 0x3e, 0x46, 0xa5,
      0xc6, 0x99, 0x4e, 0x35,
      0x55, 0x50, 0x1c, 0xba,
      0xc0, 0x7c, 0x06, 0x77
    }
  };

  input_transaction_t *txin_p = &txin;
  output_transaction_t *txout_p = &txout;
  transaction_t tx = {
    .txin_count = 1,
    .txout_count = 1,
    .txins = &txin_p,
    .txouts = &txout_p
  };

  transaction_t *tx_p = &tx;

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  // create txin signature
  crypto_sign_keypair(pk, sk);
  ASSERT(sign_txin(txin_p, tx_p, pk, sk) == 0);

  ASSERT_MEM_EQ(pk, txin_p->public_key, crypto_sign_PUBLICKEYBYTES);

  // verify the txin signature
  ASSERT(validate_txin_signature(tx_p, txin_p) == 0);
  ASSERT(validate_tx_signatures(tx_p) == 0);
  PASS();
}

TEST can_serialize_tx(void)
{
  input_transaction_t txin = {
    .transaction = {
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
    },
    .txout_index = 0
  };

  output_transaction_t txout = {
    .amount = 50,
    .address = {
      0x01, 0x3e, 0x46, 0xa5,
      0xc6, 0x99, 0x4e, 0x35,
      0x55, 0x50, 0x1c, 0xba,
      0xc0, 0x7c, 0x06, 0x77
    }
  };

  input_transaction_t *txin_p = &txin;
  output_transaction_t *txout_p = &txout;
  transaction_t tx = {
    .txout_count = 1,
    .txouts = &txout_p
  };

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  sign_txin(&txin, &tx, pk, sk);

  tx.txin_count = 1;
  tx.txins = &txin_p;

  uint8_t *buffer = NULL;
  uint32_t buffer_len;

  transaction_to_serialized(&buffer, &buffer_len, &tx);

  ASSERT(buffer != NULL);
  ASSERT(buffer_len > 0);

  free(buffer);
  PASS();
}

GREATEST_SUITE(transaction_suite)
{
  RUN_TEST(can_sign_txin);
  RUN_TEST(can_serialize_tx);
}
