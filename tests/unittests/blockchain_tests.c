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

#include "crypto/cryptoutil.h"

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

TEST can_insert_block(void)
{
  block_t *block = make_block();
  memcpy(block->hash, block_hash, HASH_SIZE);
  block->nonce = 123456;
  block->transaction_count = 0;

  insert_block(block, 0);
  block_t *block_from_db = get_block_from_hash(block->hash);

  ASSERT_MEM_EQ(block->hash, block_hash, HASH_SIZE);
  ASSERT_EQ(block->nonce, 123456);

  free_block(block);
  free_block(block_from_db);
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
  block->transactions = malloc(sizeof(transaction_t) * block->transaction_count);
  block->transactions[0] = tx;

  insert_block(block, 0);
  uint8_t *block_hash_from_tx = get_block_hash_from_tx_id(tx_id);

  if (block_hash_from_tx != NULL)
  {
    ASSERT_MEM_EQ(block->hash, block_hash_from_tx, HASH_SIZE);
    free_block(block);
    free(block_hash_from_tx);
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
  block->transactions = malloc(sizeof(transaction_t) * block->transaction_count);
  block->transactions[0] = tx;

  insert_block(block, 0);
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

  ASSERT(insert_block(block, 0) == 0);
  ASSERT(has_block_by_hash(block_hash) == 1);
  block_t *block_from_db = get_block_from_hash(block_hash);
  ASSERT(block_from_db != NULL);

  delete_block_from_blockchain(block_hash);
  block_t *deleted_block = get_block_from_hash(block_hash);
  ASSERT(deleted_block == NULL);
  ASSERT(has_block_by_hash(block_hash) == 0);

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
  block->transactions = malloc(sizeof(transaction_t) * 1);
  block->transactions[0] = tx;

  insert_block(block, 0);
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

  insert_tx_into_unspent_index(&tx);
  unspent_transaction_t *unspent_tx = get_unspent_tx_from_index(tx.id);

  if (unspent_tx != NULL)
  {
    output_transaction_t *txout = tx.txouts[0];
    unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[0];
    ASSERT(txout != NULL);
    ASSERT(unspent_txout != NULL);
    ASSERT_MEM_EQ(txout->address, unspent_txout->address, HASH_SIZE);

    delete_unspent_tx_from_index(tx.id);
    unspent_transaction_t *deleted_tx = get_unspent_tx_from_index(tx.id);
    ASSERT(deleted_tx == NULL);
    free_unspent_transaction(unspent_tx);

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
  tx->txouts = malloc(sizeof(output_transaction_t) * tx->txout_count);
  tx->txouts[0] = txout;

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  sign_txin(txin, tx, pk, sk);

  tx->txin_count = 1;
  tx->txins = malloc(sizeof(input_transaction_t) * tx->txin_count);
  tx->txins[0] = txin;
  compute_self_tx_id(tx);

  block_t *block = make_block();
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t) * block->transaction_count);
  block->transactions[0] = tx;

  insert_block(block, 0);
  unspent_transaction_t *unspent_tx = get_unspent_tx_from_index(tx->id);
  free_block(block);

  if (unspent_tx != NULL)
  {
    ASSERT(unspent_tx->unspent_txout_count == 1);
    ASSERT(unspent_tx->unspent_txouts[0]->spent == 0);

    input_transaction_t *txin_2 = malloc(sizeof(input_transaction_t));
    output_transaction_t *txout_2 = malloc(sizeof(output_transaction_t));

    txin_2->txout_index = 0;
    txout_2->amount = 50;
    memcpy(txin_2->transaction, unspent_tx->id, HASH_SIZE);
    memcpy(txout_2->address, address, HASH_SIZE);

    transaction_t *tx_2 = malloc(sizeof(transaction_t));
    tx_2->txout_count = 1;
    tx_2->txouts = malloc(sizeof(output_transaction_t) * 1);
    tx_2->txouts[0] = txout_2;

    crypto_sign_keypair(pk, sk);
    sign_txin(txin_2, tx_2, pk, sk);

    tx_2->txin_count = 1;
    tx_2->txins = malloc(sizeof(input_transaction_t) * 1);
    tx_2->txins[0] = txin_2;
    compute_self_tx_id(tx_2);

    block_t *block_2 = make_block();
    block_2->transaction_count = 1;
    block_2->transactions = malloc(sizeof(transaction_t) * 1);
    block_2->transactions[0] = tx_2;

    insert_block(block_2, 0);

    unspent_transaction_t *unspent_tx_2 = get_unspent_tx_from_index(unspent_tx->id);

    ASSERT(unspent_tx_2 == NULL);

    if (unspent_tx_2 != NULL)
    {
      free_unspent_transaction(unspent_tx_2);
    }

    free_unspent_transaction(unspent_tx);
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
  tx->txouts = malloc(sizeof(output_transaction_t) * 1);
  tx->txouts[0] = txout;

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  sign_txin(txin, tx, pk, sk);

  tx->txin_count = 1;
  tx->txins = malloc(sizeof(input_transaction_t) * tx->txin_count);
  tx->txins[0] = txin;
  compute_self_tx_id(tx);

  block_t *block = make_block();
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t) * block->transaction_count);
  block->transactions[0] = tx;

  insert_block(block, 0);
  unspent_transaction_t *unspent_tx = get_unspent_tx_from_index(tx->id);
  free_block(block);

  if (unspent_tx != NULL)
  {
    ASSERT(unspent_tx->unspent_txout_count == 1);
    ASSERT(unspent_tx->unspent_txouts[0]->spent == 0);

    input_transaction_t *txin_2 = malloc(sizeof(input_transaction_t));
    output_transaction_t *txout_2 = malloc(sizeof(output_transaction_t));

    txin_2->txout_index = 0;
    txout_2->amount = 50;
    memcpy(txin_2->transaction, unspent_tx->id, HASH_SIZE);
    memcpy(txout_2->address, address, HASH_SIZE);

    transaction_t *tx_2 = malloc(sizeof(transaction_t));
    tx_2->txout_count = 1;
    tx_2->txouts = malloc(sizeof(output_transaction_t) * tx_2->txout_count);
    tx_2->txouts[0] = txout_2;

    crypto_sign_keypair(pk, sk);
    sign_txin(txin_2, tx_2, pk, sk);

    tx_2->txin_count = 1;
    tx_2->txins = malloc(sizeof(input_transaction_t) * tx_2->txin_count);
    tx_2->txins[0] = txin_2;
    compute_self_tx_id(tx_2);

    ASSERT(valid_transaction(tx_2) == 1);

    free_unspent_transaction(unspent_tx);

    PASS();
  }
  else
  {
    FAIL();
  }
}

TEST can_backup_and_restore_blockchain(void)
{
  // construct a block to add
  block_t *block = make_block();
  block->version = 1;

  char *previous_hash_str = "a027c3999b9ad6d40e5e810ff6889937c1e84cc0f2fe9101330029f0f17f29f4";
  size_t out_size = 0;
  uint8_t *previous_hash = hex2bin(previous_hash_str, &out_size);
  ASSERT(out_size == HASH_SIZE);
  memcpy(block->previous_hash, previous_hash, HASH_SIZE);

  char *hash_str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  uint8_t *hash = hex2bin(hash_str, &out_size);
  ASSERT(out_size == HASH_SIZE);
  memcpy(block->hash, hash, HASH_SIZE);

  block->timestamp = 1563488568;
  block->nonce = 1033119846;
  block->bits = 0x1d00ffff;
  block->cumulative_emission = 6103515625;

  char *merkle_root_str = "163174b3729c593f3b6e7d4ea119a4c5b13008c6fce3794a27af75cf3b56e6f6";
  uint8_t *merkle_root = hex2bin(merkle_root_str, &out_size);
  ASSERT(out_size == HASH_SIZE);
  memcpy(block->merkle_root, merkle_root, HASH_SIZE);

  // clear our blockchains
  ASSERT(reset_blockchain() == 0);

  // add a block to the main blockchain
  ASSERT(insert_block(block, 0) == 0);
  ASSERT(get_block_height() == 0);
  ASSERT(has_block_by_hash(block->hash) == 1);

  // backup our blockchain
  ASSERT(backup_blockchain() == 0);

  // clear the blockchain
  ASSERT(reset_blockchain() == 0);

  // check to see if our main blockchain is empty
  ASSERT(get_block_height() == 0);
  ASSERT(has_block_by_hash(block->hash) == 0);

  // restore our blockchain
  ASSERT(restore_blockchain() == 0);

  // check to see if our main blockchain has been restored
  ASSERT(get_block_height() == 0);
  ASSERT(has_block_by_hash(block->hash) == 1);

  block_t *block1 = get_block_from_hash(block->hash);
  ASSERT(block1 != NULL);
  ASSERT(compare_block(block, block1) == 1);

  PASS();
}

GREATEST_SUITE(blockchain_suite)
{
  RUN_TEST(can_insert_block);
  RUN_TEST(inserting_block_into_blockchain_also_inserts_tx);
  RUN_TEST(can_get_block_from_tx_id);
  RUN_TEST(can_delete_block_from_blockchain);
  RUN_TEST(can_delete_tx_from_index);
  RUN_TEST(can_insert_unspent_tx_into_index);
  RUN_TEST(inserting_block_into_blockchain_marks_txouts_as_spent);
  RUN_TEST(tx_is_valid_only_if_it_has_money_unspent);
  RUN_TEST(can_backup_and_restore_blockchain);
}
