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
  input_transaction_t *txin = make_txin();
  output_transaction_t *txout = make_txout();
  txout->amount = 50;

  // copy the address to the txout
  char *address_str = "02bb3d97634bd6a3973cfd1d88450f2cff26a80a76fd18d58afd10a3dca18a85fa";
  size_t out_size = 0;
  uint8_t *address = hex2bin(address_str, &out_size);
  ASSERT(out_size == ADDRESS_SIZE);
  memcpy(txout->address, address, ADDRESS_SIZE);

  transaction_t *tx = make_transaction();
  ASSERT(add_txin_to_transaction(tx, txin, 0) == 0);
  ASSERT(add_txout_to_transaction(tx, txout, 0) == 0);

  // create txin signature
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  ASSERT(sign_txin(txin, tx, pk, sk) == 0);

  // verify the txin signature
  ASSERT_MEM_EQ(pk, txin->public_key, crypto_sign_PUBLICKEYBYTES);

  ASSERT(validate_txin_signature(tx, txin) == 0);
  ASSERT(validate_tx_signatures(tx) == 0);

  free_transaction(tx);
  PASS();
}

TEST can_serialize_and_deserialize_tx(void)
{
  input_transaction_t *txin = make_txin();
  output_transaction_t *txout = make_txout();
  txout->amount = 50;

  // copy the address to the txout
  char *address_str = "02bb3d97634bd6a3973cfd1d88450f2cff26a80a76fd18d58afd10a3dca18a85fa";
  size_t out_size = 0;
  uint8_t *address = hex2bin(address_str, &out_size);
  ASSERT(out_size == ADDRESS_SIZE);
  memcpy(txout->address, address, ADDRESS_SIZE);

  transaction_t *tx = make_transaction();
  ASSERT(add_txin_to_transaction(tx, txin, 0) == 0);
  ASSERT(add_txout_to_transaction(tx, txout, 0) == 0);

  // create txin signature
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  ASSERT(sign_txin(txin, tx, pk, sk) == 0);

  // serialize and deserialize the tx
  buffer_t *buffer = buffer_init();
  ASSERT(buffer != NULL);
  ASSERT(serialize_transaction(buffer, tx) == 0);

  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);
  ASSERT(buffer_iterator != NULL);

  transaction_t *deserialized_tx = NULL;
  ASSERT(deserialize_transaction(buffer_iterator, &deserialized_tx) == 0);
  ASSERT(compare_transaction(deserialized_tx, tx) == 1);

  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);

  free_transaction(deserialized_tx);
  free_transaction(tx);
  PASS();
}

TEST can_copy_tx(void)
{
  input_transaction_t *txin = make_txin();
  output_transaction_t *txout = make_txout();
  txout->amount = 50;

  // copy the address to the txout
  char *address_str = "02bb3d97634bd6a3973cfd1d88450f2cff26a80a76fd18d58afd10a3dca18a85fa";
  size_t out_size = 0;
  uint8_t *address = hex2bin(address_str, &out_size);
  ASSERT(out_size == ADDRESS_SIZE);
  memcpy(txout->address, address, ADDRESS_SIZE);

  transaction_t *tx = make_transaction();
  ASSERT(add_txin_to_transaction(tx, txin, 0) == 0);
  ASSERT(add_txout_to_transaction(tx, txout, 0) == 0);

  // create txin signature
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  ASSERT(sign_txin(txin, tx, pk, sk) == 0);

  // copy the transaction and test it
  transaction_t *new_tx = make_transaction();
  ASSERT(copy_transaction(tx, new_tx) == 0);
  ASSERT(compare_transaction(new_tx, tx) == 1);

  free_transaction(new_tx);
  free_transaction(tx);
  PASS();
}

GREATEST_SUITE(transaction_suite)
{
  RUN_TEST(can_sign_txin);
  RUN_TEST(can_serialize_and_deserialize_tx);
  RUN_TEST(can_copy_tx);
}
