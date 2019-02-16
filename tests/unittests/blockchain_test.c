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

#include "common/greatest.h"
#include "common/util.h"

#include "core/block.h"
#include "core/blockchain.h"

SUITE(blockchain_suite);

static uint8_t block_hash[HASH_SIZE] = {
  0x01, 0x02, 0x03, 0x04,
  0x01, 0x02, 0x03, 0x04,
  0x01, 0x02, 0x03, 0x04,
  0x01, 0x02, 0x03, 0x04,
  0x01, 0x02, 0x03, 0x04,
  0x01, 0x02, 0x03, 0x04,
  0x01, 0x02, 0x03, 0x04,
  0x01, 0x02, 0x03, 0x04
};

static uint8_t tx_id[HASH_SIZE] = {
  0x04, 0x03, 0x02, 0x01,
  0x04, 0x03, 0x02, 0x01,
  0x04, 0x03, 0x02, 0x01,
  0x04, 0x03, 0x02, 0x01,
  0x04, 0x03, 0x02, 0x01,
  0x04, 0x03, 0x02, 0x01,
  0x04, 0x03, 0x02, 0x01,
  0x04, 0x03, 0x02, 0x01
};

TEST check_blocks_in_blockchain(void)
{
  ASSERT_EQ(has_block_by_hash(genesis_block.hash), 1);
  ASSERT_EQ(has_block_by_height(0), 1);

  ASSERT(get_block_from_height(0) != NULL);
  ASSERT(get_block_from_hash(genesis_block.hash) != NULL);

  ASSERT_EQ(get_block_height_from_hash(genesis_block.hash), 0);
  ASSERT_EQ(get_block_height_from_block(&genesis_block), 0);
  ASSERT(compare_block_hash(get_block_hash_from_height(0), genesis_block.hash));

  PASS();
}

TEST can_insert_block(void)
{
  block_t *block = make_block();
  memcpy(block->hash, block_hash, HASH_SIZE);
  block->nonce = 123456;
  block->transaction_count = 0;

  insert_block(block);
  block_t *block_from_db = get_block_from_hash(block->hash);

  ASSERT_MEM_EQ(block->hash, block_hash, HASH_SIZE);
  ASSERT_EQ(block->nonce, 123456);

  free_block(block);

  PASS();
}

TEST inserting_block_into_blockchain_also_inserts_tx(void)
{
  transaction_t *tx = malloc(sizeof(transaction_t));
  memcpy(tx->id, tx_id, HASH_SIZE);
  tx->txin_count = 0;
  tx->txout_count = 0;
  tx->txins = NULL;
  tx->txouts = NULL;

  block_t *block = make_block();
  memcpy(block->hash, block_hash, HASH_SIZE);
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t *) * block->transaction_count);
  block->transactions[0] = tx;

  insert_block(block);
  uint8_t *block_hash_from_tx = get_block_hash_from_tx_id(tx_id);

  if (block_hash_from_tx != NULL)
  {
    ASSERT_MEM_EQ(block->hash, block_hash_from_tx, HASH_SIZE);
    free_block(block);
    PASS();
  }
  else
  {
    free_block(block);
    FAIL();
  }
}

TEST can_get_block_from_tx_id(void)
{
  transaction_t *tx = malloc(sizeof(transaction_t));
  memcpy(tx->id, tx_id, HASH_SIZE);
  tx->txin_count = 0;
  tx->txout_count = 0;
  tx->txins = NULL;
  tx->txouts = NULL;

  block_t *block = make_block();
  memcpy(block->hash, block_hash, HASH_SIZE);
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t *) * block->transaction_count);
  block->transactions[0] = tx;

  insert_block(block);
  block_t *block_from_db = get_block_from_tx_id(tx_id);

  if (block_from_db != NULL)
  {
    ASSERT_MEM_EQ(block->hash, block_from_db->hash, HASH_SIZE);
    free_block(block);
    free_block(block_from_db);
    PASS();
  }
  else
  {
    free_block(block);
    FAIL();
  }
}

TEST can_delete_block_from_blockchain(void)
{
  block_t *block = make_block();
  memcpy(block->hash, block_hash, HASH_SIZE);

  insert_block(block);
  block_t *block_from_db = get_block_from_hash(block_hash);

  ASSERT(block_from_db != NULL);

  delete_block_from_blockchain(block_hash);
  block_t *deleted_block = get_block_from_hash(block_hash);

  ASSERT(deleted_block == NULL);

  free_block(block);
  free_block(block_from_db);

  return 0;
}

TEST can_delete_tx_from_index(void)
{
  transaction_t *tx = malloc(sizeof(transaction_t));
  memcpy(tx->id, tx_id, HASH_SIZE);
  tx->txin_count = 0;
  tx->txout_count = 0;
  tx->txins = NULL;
  tx->txouts = NULL;

  block_t *block = make_block();
  memcpy(block->hash, block_hash, HASH_SIZE);
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t *) * 1);
  block->transactions[0] = tx;

  insert_block(block);
  block_t *block_from_db = get_block_from_tx_id(tx_id);

  if (block_from_db != NULL)
  {
    ASSERT_MEM_EQ(block->hash, block_from_db->hash, HASH_SIZE);

    delete_tx_from_index(tx_id);
    block_t *deleted_block = get_block_from_tx_id(tx_id);

    ASSERT(deleted_block == NULL);

    free_block(block);
    free_block(block_from_db);

    PASS();
  }
  else
  {
    free_block(block);
    FAIL();
  }
}

TEST can_insert_unspent_tx_into_index(void)
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

  output_transaction_t *txout_p = &txout;
  transaction_t tx = {
    .txin_count = 0,
    .txout_count = 1,
    .txouts = &txout_p
  };

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  sign_txin(&txin, &tx, pk, sk);

  insert_unspent_tx_into_index(&tx);
  PUnspentTransaction *unspent_tx = get_unspent_tx_from_index(tx.id);

  if (unspent_tx != NULL)
  {
    ASSERT_MEM_EQ(tx.txouts[0]->address, unspent_tx->unspent_txouts[0]->address.data, HASH_SIZE);
    delete_unspent_tx_from_index(tx.id);
    PUnspentTransaction *deleted_tx = get_unspent_tx_from_index(tx.id);

    ASSERT(deleted_tx == NULL);

    free_proto_unspent_transaction(unspent_tx);

    PASS();
  }
  else
  {
    FAIL();
  }
}

TEST inserting_block_into_blockchain_marks_txouts_as_spent(void)
{
  uint8_t transaction[HASH_SIZE] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };

  uint8_t address[HASH_SIZE] = {
    0x01, 0x3e, 0x46, 0xa5,
    0xc6, 0x99, 0x4e, 0x35,
    0x55, 0x50, 0x1c, 0xba,
    0xc0, 0x7c, 0x06, 0x77
  };

  input_transaction_t *txin = malloc(sizeof(input_transaction_t));
  output_transaction_t *txout = malloc(sizeof(output_transaction_t));

  txin->txout_index = 0;
  txout->amount = 50;
  memcpy(txin->transaction, transaction, HASH_SIZE);
  memcpy(txout->address, address, HASH_SIZE);

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
  compute_self_tx_id(tx);

  block_t *block = make_block();
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t *) * block->transaction_count);
  block->transactions[0] = tx;

  insert_block(block);
  PUnspentTransaction *unspent_tx = get_unspent_tx_from_index(tx->id);
  free_block(block);

  if (unspent_tx != NULL)
  {
    ASSERT(unspent_tx->n_unspent_txouts == 1);
    ASSERT(unspent_tx->unspent_txouts[0]->spent == 0);

    input_transaction_t *txin_2 = malloc(sizeof(input_transaction_t));
    output_transaction_t *txout_2 = malloc(sizeof(output_transaction_t));

    txin_2->txout_index = 0;
    txout_2->amount = 50;
    memcpy(txin_2->transaction, unspent_tx->id.data, HASH_SIZE);
    memcpy(txout_2->address, address, HASH_SIZE);

    transaction_t *tx_2 = malloc(sizeof(transaction_t));
    tx_2->txout_count = 1;
    tx_2->txouts = malloc(sizeof(output_transaction_t *) * 1);
    tx_2->txouts[0] = txout_2;

    crypto_sign_keypair(pk, sk);
    sign_txin(txin_2, tx_2, pk, sk);

    tx_2->txin_count = 1;
    tx_2->txins = malloc(sizeof(input_transaction_t *) * 1);
    tx_2->txins[0] = txin_2;
    compute_self_tx_id(tx_2);

    block_t *block_2 = make_block();
    block_2->transaction_count = 1;
    block_2->transactions = malloc(sizeof(transaction_t *) * 1);
    block_2->transactions[0] = tx_2;

    insert_block(block_2);

    PUnspentTransaction *unspent_tx_2 = get_unspent_tx_from_index(unspent_tx->id.data);

    ASSERT(unspent_tx_2 == NULL);

    if (unspent_tx_2 != NULL)
    {
      free_proto_unspent_transaction(unspent_tx_2);
    }

    free_proto_unspent_transaction(unspent_tx);
    free_block(block_2);

    PASS();
  }
  else
  {
    FAIL();
  }
}

TEST tx_is_valid_only_if_it_has_money_unspent(void)
{
  uint8_t transaction[HASH_SIZE] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };

  uint8_t address[HASH_SIZE] = {
    0x01, 0x3e, 0x46, 0xa5,
    0xc6, 0x99, 0x4e, 0x35,
    0x55, 0x50, 0x1c, 0xba,
    0xc0, 0x7c, 0x06, 0x77
  };

  input_transaction_t *txin = malloc(sizeof(input_transaction_t));
  output_transaction_t *txout = malloc(sizeof(output_transaction_t));

  txin->txout_index = 0;
  txout->amount = 50;
  memcpy(txin->transaction, transaction, HASH_SIZE);
  memcpy(txout->address, address, HASH_SIZE);

  transaction_t *tx = malloc(sizeof(transaction_t));
  tx->txout_count = 1;
  tx->txouts = malloc(sizeof(output_transaction_t *) * 1);
  tx->txouts[0] = txout;

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  sign_txin(txin, tx, pk, sk);

  tx->txin_count = 1;
  tx->txins = malloc(sizeof(input_transaction_t *) * tx->txin_count);
  tx->txins[0] = txin;
  compute_self_tx_id(tx);

  block_t *block = make_block();
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t *) * block->transaction_count);
  block->transactions[0] = tx;

  insert_block(block);
  PUnspentTransaction *unspent_tx = get_unspent_tx_from_index(tx->id);
  free_block(block);

  if (unspent_tx != NULL)
  {
    ASSERT(unspent_tx->n_unspent_txouts == 1);
    ASSERT(unspent_tx->unspent_txouts[0]->spent == 0);

    input_transaction_t *txin_2 = malloc(sizeof(input_transaction_t));
    output_transaction_t *txout_2 = malloc(sizeof(output_transaction_t));

    txin_2->txout_index = 0;
    txout_2->amount = 50;
    memcpy(txin_2->transaction, unspent_tx->id.data, HASH_SIZE);
    memcpy(txout_2->address, address, HASH_SIZE);

    transaction_t *tx_2 = malloc(sizeof(transaction_t));
    tx_2->txout_count = 1;
    tx_2->txouts = malloc(sizeof(output_transaction_t *) * tx_2->txout_count);
    tx_2->txouts[0] = txout_2;

    crypto_sign_keypair(pk, sk);
    sign_txin(txin_2, tx_2, pk, sk);

    tx_2->txin_count = 1;
    tx_2->txins = malloc(sizeof(input_transaction_t *) * tx_2->txin_count);
    tx_2->txins[0] = txin_2;
    compute_self_tx_id(tx_2);

    ASSERT(valid_transaction(tx_2) == 1);

    free_proto_unspent_transaction(unspent_tx);

    PASS();
  }
  else
  {
    FAIL();
  }
}

GREATEST_SUITE(blockchain_suite)
{
  RUN_TEST(check_blocks_in_blockchain);
  RUN_TEST(can_insert_block);
  RUN_TEST(inserting_block_into_blockchain_also_inserts_tx);
  RUN_TEST(can_get_block_from_tx_id);
  RUN_TEST(can_delete_block_from_blockchain);
  RUN_TEST(can_delete_tx_from_index);
  RUN_TEST(can_insert_unspent_tx_into_index);
  RUN_TEST(inserting_block_into_blockchain_marks_txouts_as_spent);
  RUN_TEST(tx_is_valid_only_if_it_has_money_unspent);
}
