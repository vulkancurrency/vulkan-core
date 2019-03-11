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
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include <sodium.h>

#include "common/buffer.h"
#include "common/logger.h"
#include "common/util.h"

#include "core/blockchain.h"
#include "core/transaction.h"

#include "crypto/sha256d.h"

#include "wallet/wallet.h"

static uint8_t g_transaction_zero_hash[HASH_SIZE] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

/*
 * This function takes in:
 * - a single TXIN to sign for.
 * - a partially filled out TX that contains all the TXOUTs to sign for.
 * - public key for signature + address verification
 * - secret key to sign
 */
int sign_txin(input_transaction_t *txin, transaction_t *tx, uint8_t *public_key, uint8_t *secret_key)
{
  uint32_t header_size = get_tx_sign_header_size(tx) + TXIN_HEADER_SIZE;
  uint8_t header[header_size];
  uint8_t hash[HASH_SIZE];

  get_txin_header(header, txin);
  get_tx_sign_header(header + TXIN_HEADER_SIZE, tx);
  crypto_hash_sha256d(hash, header, header_size);
  crypto_sign_detached(txin->signature, NULL, header, header_size, secret_key);
  memcpy(&txin->public_key, public_key, crypto_sign_PUBLICKEYBYTES);

  return 0;
}

int get_txin_header(uint8_t *header, input_transaction_t *txin)
{
  memcpy(header, &txin->transaction, HASH_SIZE);
  memcpy(header + HASH_SIZE, &txin->txout_index, 4);
  return 0;
}

int get_txout_header(uint8_t *header, output_transaction_t *txout)
{
  memcpy(header, &txout->amount, 4);
  memcpy(header, &txout->address, ADDRESS_SIZE);
  return 0;
}

uint32_t get_tx_header_size(transaction_t *tx)
{
  uint32_t txin_header_sizes = TXIN_HEADER_SIZE * tx->txin_count;
  uint32_t txout_header_sizes = TXOUT_HEADER_SIZE * tx->txout_count;
  return txin_header_sizes + txout_header_sizes;
}

/*
 * The reason why sign header is different from full header is that
 * the signing header only contains TXOUTs. This is used in the context
 * for a TXIN, as it needs to sign consent to spend value to these
 * TXOUTs.
 */
uint32_t get_tx_sign_header_size(transaction_t *tx)
{
  uint32_t txout_header_sizes = TXOUT_HEADER_SIZE * tx->txout_count;
  return txout_header_sizes;
}

int get_tx_sign_header(uint8_t *header, transaction_t *tx)
{
  for (int i = 0; i < tx->txout_count; i++)
  {
    get_txout_header(header + (TXOUT_HEADER_SIZE * i), tx->txouts[i]);
  }

  return 0;
}

int compare_transaction_hash(uint8_t *id, uint8_t *other_id)
{
  return memcmp(id, other_id, HASH_SIZE) == 0;
}

int compare_transaction(transaction_t *transaction, transaction_t *other_transaction)
{
  return compare_transaction_hash(transaction->id, other_transaction->id);
}

void print_txin(uint8_t txin_index, input_transaction_t *txin)
{
  assert(txin != NULL);

  printf("Txin %d:\n", txin_index);
  printf("Previous Tx: %s\n", hash_to_str(txin->transaction));
  printf("Index: %d\n", txin->txout_index);
  printf("Signature: %s\n", bytes_to_str(txin->signature, crypto_sign_BYTES));
  printf("Public Key: %s\n", bytes_to_str(txin->public_key, crypto_sign_PUBLICKEYBYTES));
}

void print_txout(uint8_t txout_index, output_transaction_t *txout)
{
  assert(txout != NULL);

  printf("Txout %d:\n", txout_index);
  printf("Amount: %llu\n", txout->amount);
  printf("Address: %s\n", address_to_str(txout->address));
}

void print_transaction(transaction_t *tx)
{
  assert(tx != NULL);

  printf("Transaction:\n");
  printf("Id: %s\n", hash_to_str(tx->id));
  printf("Txin Count: %d\n", tx->txin_count);
  printf("Txout Count: %d\n", tx->txout_count);
  printf("\n");

  // print txins
  for (int i = 0; i < tx->txin_count; i++)
  {
    input_transaction_t *txin = tx->txins[i];
    assert(txin != NULL);

    print_txin(i, txin);
    printf("\n");
  }

  // print txouts
  for (int i = 0; i < tx->txout_count; i++)
  {
    output_transaction_t *txout = tx->txouts[i];
    assert(txout != NULL);

    print_txout(i, txout);
    printf("\n");
  }
}

/*
 * A transaction is valid if:
 * - It's header size is less than that of defined as MAX_TX_SIZE
 * - It is a generation tx
 * - It has TXINs that reference valid unspent TXOUTs
 * - Its combined TXIN UTXO values equal the combined amount of TXOUTs.
 */
int valid_transaction(transaction_t *tx)
{
  if (tx->txin_count > 0 && tx->txout_count > 0)
  {
    uint32_t tx_header_size = get_tx_header_size(tx);
    if (tx_header_size > MAX_TX_SIZE)
    {
      LOG_DEBUG("Transaction has too big header blob size: %d!", tx_header_size);
      return 0;
    }

    if (is_generation_tx(tx))
    {
      return 1;
    }

    if (do_txins_reference_unspent_txouts(tx))
    {
      return 1;
    }
  }

  return 0;
}

int do_txins_reference_unspent_txouts(transaction_t *tx)
{
  int valid_txins = 0;
  int input_money = 0;
  int required_money = 0;

  for (int i = 0; i < tx->txin_count; i++)
  {
    input_transaction_t *txin = tx->txins[i];
    assert(txin != NULL);

    unspent_transaction_t *unspent_tx = get_unspent_tx_from_index(txin->transaction);
    if (unspent_tx != NULL)
    {
      if (((unspent_tx->unspent_txout_count - 1) < txin->txout_index) ||
          (unspent_tx->unspent_txouts[txin->txout_index] == NULL))
      {

      }
      else
      {
        unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[txin->txout_index];
        assert(unspent_txout != NULL);

        if (unspent_txout->spent == 0)
        {
          input_money += unspent_txout->amount;
          valid_txins++;
        }
      }

      free_unspent_transaction(unspent_tx);
    }
  }

  for (int i = 0; i < tx->txout_count; i++)
  {
    output_transaction_t *txout = tx->txouts[i];
    assert(txout != NULL);
    required_money += txout->amount;

    if (valid_address(txout->address) == 0)
    {
      return 0;
    }
  }

  return (valid_txins == tx->txin_count) && (input_money == required_money);
}

int is_generation_tx(transaction_t *tx)
{
  return (tx->txin_count == 1 && tx->txout_count == 1 && memcmp(tx->txins[0]->transaction, g_transaction_zero_hash, HASH_SIZE) == 0);
}

int compute_tx_id(uint8_t *header, transaction_t *tx)
{
  uint8_t *buffer = NULL;
  uint32_t buffer_len = 0;

  transaction_to_serialized(&buffer, &buffer_len, tx);
  crypto_hash_sha256d(header, buffer, buffer_len);
  free(buffer);

  return 0;
}

int compute_self_tx_id(transaction_t *tx)
{
  compute_tx_id(tx->id, tx);
  return 0;
}

int serialize_txin(buffer_t *buffer, input_transaction_t *txin)
{
  assert(buffer != NULL);
  assert(txin != NULL);

  buffer_write_bytes(buffer, txin->transaction, HASH_SIZE);
  buffer_write_uint32(buffer, txin->txout_index);

  // when writing the signature and public key bytes,
  // pull the size of the reference instead of manually specifying
  // the size, as this value could potentially change...
  buffer_write_bytes(buffer, txin->signature, sizeof(txin->signature));
  buffer_write_bytes(buffer, txin->public_key, sizeof(txin->public_key));
  return 0;
}

input_transaction_t* deserialize_txin(buffer_t *buffer)
{
  assert(buffer != NULL);

  input_transaction_t *txin = malloc(sizeof(input_transaction_t));

  uint8_t *prev_tx_id = buffer_read_bytes(buffer);
  memcpy(txin->transaction, prev_tx_id, HASH_SIZE);

  txin->txout_index = buffer_read_uint32(buffer);

  uint8_t *signature = buffer_read_bytes(buffer);
  memcpy(txin->signature, signature, sizeof(txin->signature));

  uint8_t *public_key = buffer_read_bytes(buffer);
  memcpy(txin->public_key, public_key, sizeof(txin->public_key));

  free(prev_tx_id);
  free(signature);
  free(public_key);

  return txin;
}

int serialize_txout(buffer_t *buffer, output_transaction_t *txout)
{
  assert(buffer != NULL);
  assert(txout != NULL);

  buffer_write_uint64(buffer, txout->amount);
  buffer_write_bytes(buffer, txout->address, ADDRESS_SIZE);
  return 0;
}

output_transaction_t* deserialize_txout(buffer_t *buffer)
{
  assert(buffer != NULL);

  output_transaction_t *txout = malloc(sizeof(output_transaction_t));
  txout->amount = buffer_read_uint64(buffer);

  uint8_t *address = buffer_read_bytes(buffer);
  memcpy(txout->address, address, ADDRESS_SIZE);

  free(address);
  return txout;
}

int serialize_transaction(buffer_t *buffer, transaction_t *tx)
{
  assert(buffer != NULL);
  assert(tx != NULL);

  buffer_write_bytes(buffer, tx->id, HASH_SIZE);
  buffer_write_uint32(buffer, tx->txin_count);
  buffer_write_uint32(buffer, tx->txout_count);

  // write txins
  for (int i = 0; i < tx->txin_count; i++)
  {
    input_transaction_t *txin = tx->txins[i];
    assert(txin != NULL);

    if (serialize_txin(buffer, txin))
    {
      return 1;
    }
  }

  // write txouts
  for (int i = 0; i < tx->txout_count; i++)
  {
    output_transaction_t *txout = tx->txouts[i];
    assert(txout != NULL);

    if (serialize_txout(buffer, txout))
    {
      return 1;
    }
  }

  return 0;
}

transaction_t* deserialize_transaction(buffer_t *buffer)
{
  assert(buffer != NULL);

  transaction_t *tx = malloc(sizeof(transaction_t));

  uint8_t *id = buffer_read_bytes(buffer);
  memcpy(tx->id, id, HASH_SIZE);

  tx->txin_count = buffer_read_uint32(buffer);
  tx->txout_count = buffer_read_uint32(buffer);

  tx->txins = malloc(sizeof(input_transaction_t) * tx->txin_count);
  tx->txouts = malloc(sizeof(output_transaction_t) * tx->txout_count);

  // read txins
  for (int i = 0; i < tx->txin_count; i++)
  {
    input_transaction_t *txin = deserialize_txin(buffer);
    assert(txin != NULL);
    tx->txins[i] = txin;
  }

  // read txouts
  for (int i = 0; i < tx->txout_count; i++)
  {
    output_transaction_t *txout = deserialize_txout(buffer);
    assert(txout != NULL);
    tx->txouts[i] = txout;
  }

  free(id);
  return tx;
}

int transaction_to_serialized(uint8_t **data, uint32_t *data_len, transaction_t *tx)
{
  assert(tx != NULL);

  buffer_t *buffer = buffer_init();
  if (serialize_transaction(buffer, tx))
  {
    return 1;
  }

  uint32_t raw_data_len = buffer_get_size(buffer);
  uint8_t *raw_data = malloc(raw_data_len);
  memcpy(raw_data, buffer->data, raw_data_len);

  *data_len = raw_data_len;
  *data = raw_data;

  buffer_free(buffer);
  return 0;
}

transaction_t* transaction_from_serialized(uint8_t *data, uint32_t data_len)
{
  buffer_t *buffer = buffer_init_data(0, (const uint8_t*)data, data_len);
  transaction_t *tx = deserialize_transaction(buffer);
  buffer_free(buffer);
  return tx;
}

int serialize_unspent_txout(buffer_t *buffer, unspent_output_transaction_t *unspent_txout)
{
  assert(buffer != NULL);
  assert(unspent_txout != NULL);

  buffer_write_uint64(buffer, unspent_txout->amount);
  buffer_write_bytes(buffer, unspent_txout->address, ADDRESS_SIZE);
  buffer_write_uint8(buffer, unspent_txout->spent);
  return 0;
}

unspent_output_transaction_t* deserialize_unspent_txout(buffer_t *buffer)
{
  assert(buffer != NULL);

  unspent_output_transaction_t *unspent_txout = malloc(sizeof(unspent_output_transaction_t));
  unspent_txout->amount = buffer_read_uint64(buffer);

  uint8_t *address = buffer_read_bytes(buffer);
  memcpy(unspent_txout->address, address, ADDRESS_SIZE);

  unspent_txout->spent = buffer_read_uint8(buffer);

  free(address);
  return unspent_txout;
}

int serialize_unspent_transaction(buffer_t *buffer, unspent_transaction_t *unspent_tx)
{
  assert(buffer != NULL);
  assert(unspent_tx != NULL);

  buffer_write_bytes(buffer, unspent_tx->id, HASH_SIZE);
  buffer_write_uint8(buffer, unspent_tx->coinbase);
  buffer_write_uint8(buffer, unspent_tx->unspent_txout_count);

  // write unspent txouts
  for (int i = 0; i < unspent_tx->unspent_txout_count; i++)
  {
    unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[i];
    assert(unspent_txout != NULL);

    if (serialize_unspent_txout(buffer, unspent_txout))
    {
      return 1;
    }
  }

  return 0;
}

unspent_transaction_t* deserialize_unspent_transaction(buffer_t *buffer)
{
  assert(buffer != NULL);

  unspent_transaction_t *unspent_tx = malloc(sizeof(unspent_transaction_t));

  uint8_t *id = buffer_read_bytes(buffer);
  memcpy(unspent_tx->id, id, HASH_SIZE);

  unspent_tx->coinbase = buffer_read_uint8(buffer);
  unspent_tx->unspent_txout_count = buffer_read_uint8(buffer);
  unspent_tx->unspent_txouts = malloc(sizeof(unspent_output_transaction_t) * unspent_tx->unspent_txout_count);

  // read unspent txouts
  for (int i = 0; i < unspent_tx->unspent_txout_count; i++)
  {
    unspent_output_transaction_t *unspent_txout = deserialize_unspent_txout(buffer);
    assert(unspent_txout != NULL);
    unspent_tx->unspent_txouts[i] = unspent_txout;
  }

  free(id);
  return unspent_tx;
}

unspent_transaction_t* transaction_to_unspent_transaction(transaction_t *tx)
{
  assert(tx != NULL);

  unspent_transaction_t *unspent_tx = malloc(sizeof(unspent_transaction_t));
  memcpy(unspent_tx->id, tx->id, HASH_SIZE);

  unspent_tx->coinbase = is_generation_tx(tx);
  unspent_tx->unspent_txout_count = tx->txout_count;
  unspent_tx->unspent_txouts = malloc(sizeof(unspent_output_transaction_t) * tx->txout_count);

  for (int i = 0; i < unspent_tx->unspent_txout_count; i++)
  {
    output_transaction_t *txout = tx->txouts[i];
    assert(txout != NULL);

    unspent_output_transaction_t *unspent_txout = malloc(sizeof(unspent_output_transaction_t));
    unspent_txout->amount = txout->amount;
    memcpy(unspent_txout->address, txout->address, ADDRESS_SIZE);
    unspent_txout->spent = 0;
    unspent_tx->unspent_txouts[i] = unspent_txout;
  }

  return unspent_tx;
}

int unspent_transaction_to_serialized(uint8_t **data, uint32_t *data_len, unspent_transaction_t *unspent_tx)
{
  assert(unspent_tx != NULL);
  buffer_t *buffer = buffer_init();
  if (serialize_unspent_transaction(buffer, unspent_tx))
  {
    return 1;
  }

  *data_len = buffer_get_size(buffer);
  *data = malloc(*data_len);

  memcpy(*data, buffer->data, *data_len);
  buffer_free(buffer);

  return 0;
}

unspent_transaction_t* unspent_transaction_from_serialized(uint8_t *data, uint32_t data_len)
{
  buffer_t *buffer = buffer_init_data(0, (const uint8_t*)data, data_len);
  unspent_transaction_t *unspent_tx = deserialize_unspent_transaction(buffer);
  buffer_free(buffer);
  return unspent_tx;
}

input_transaction_t* make_txin(uint32_t block_height)
{
  input_transaction_t *txin = malloc(sizeof(input_transaction_t));
  memset(txin->transaction, 0, HASH_SIZE);
  txin->txout_index = block_height;
  return txin;
}

output_transaction_t* make_txout(uint8_t *address, uint64_t amount)
{
  output_transaction_t *txout = malloc(sizeof(output_transaction_t));
  txout->amount = amount;
  memcpy(txout->address, address, ADDRESS_SIZE);
  return txout;
}

transaction_t* make_tx(wallet_t *wallet, uint32_t block_height, uint64_t cumulative_emission, transaction_entries_t transaction_entries)
{
  assert(wallet != NULL);
  assert(transaction_entries.num_entries <= (uint16_t)MAX_NUM_TX_ENTRIES);
  transaction_t *tx = malloc(sizeof(transaction_t));

  tx->txout_count = transaction_entries.num_entries;
  tx->txouts = malloc(sizeof(output_transaction_t) * tx->txout_count);

  tx->txin_count = transaction_entries.num_entries;
  tx->txins = malloc(sizeof(input_transaction_t) * tx->txin_count);

  for (uint16_t i = 0; i < transaction_entries.num_entries; i++)
  {
    transaction_entry_t transaction_entry = transaction_entries.entries[i];

    input_transaction_t *txin = make_txin(block_height);
    output_transaction_t *txout = make_txout(transaction_entry.address, transaction_entry.amount);

    assert(txin != NULL);
    assert(txout != NULL);

    tx->txins[i] = txin;
    tx->txouts[i] = txout;

    sign_txin(txin, tx, wallet->public_key, wallet->secret_key);
  }

  compute_self_tx_id(tx);
  return tx;
}

transaction_t* make_generation_tx(wallet_t *wallet, uint32_t block_height, uint64_t cumulative_emission, uint64_t block_reward)
{
  transaction_entry_t transaction_entry;
  transaction_entry.address = wallet->address;
  transaction_entry.amount = block_reward;

  transaction_entries_t transaction_entries;
  transaction_entries.num_entries = 1;
  transaction_entries.entries[0] = transaction_entry;

  return make_tx(wallet, block_height, cumulative_emission, transaction_entries);
}

int copy_txin(input_transaction_t *txin, input_transaction_t *other_txin)
{
  assert(txin != NULL);
  assert(other_txin != NULL);

  memcpy(&other_txin->transaction, &txin->transaction, HASH_SIZE);
  other_txin->txout_index = txin->txout_index;

  memcpy(&other_txin->signature, &txin->signature, HASH_SIZE);
  memcpy(&other_txin->public_key, &txin->public_key, HASH_SIZE);
  return 0;
}

int copy_txout(output_transaction_t *txout, output_transaction_t *other_txout)
{
  assert(txout != NULL);
  assert(other_txout != NULL);

  other_txout->amount = txout->amount;
  memcpy(&other_txout->address, txout->address, HASH_SIZE);
  return 0;
}

int copy_transaction(transaction_t *tx, transaction_t *other_tx)
{
  assert(tx != NULL);
  assert(other_tx != NULL);

  // free old txins for the transaction we are copying to
  if (free_txins(other_tx))
  {
    return 1;
  }

  // free old txouts for the transaction we are copying to
  if (free_txouts(other_tx))
  {
    return 1;
  }

  // copy the transaction id to the transaction we are copying to
  memcpy(&other_tx->id, &tx->id, HASH_SIZE);

  if ((tx->txin_count > 0 && tx->txins != NULL) && (tx->txout_count > 0 && tx->txouts != NULL))
  {
    // allocate the txin, txout arrays for the transaction we are copying to
    other_tx->txin_count = tx->txin_count;
    other_tx->txout_count = tx->txout_count;

    other_tx->txins = malloc(sizeof(input_transaction_t) * tx->txin_count);
    other_tx->txouts = malloc(sizeof(output_transaction_t) * tx->txout_count);

    // copy the txins to the transaction we are copying to
    for (int i = 0; i < tx->txin_count; i++)
    {
      input_transaction_t *txin = tx->txins[i];
      assert(txin != NULL);

      input_transaction_t *other_txin = malloc(sizeof(input_transaction_t));
      if (copy_txin(txin, other_txin))
      {
        return 1;
      }

      assert(other_txin != NULL);
      other_tx->txins[i] = other_txin;
    }

    // copy the txouts to the transaction we are copying to
    for (int i = 0; i < tx->txout_count; i++)
    {
      output_transaction_t *txout = tx->txouts[i];
      assert(txout != NULL);

      output_transaction_t *other_txout = malloc(sizeof(output_transaction_t));
      if (copy_txout(txout, other_txout))
      {
        return 1;
      }

      assert(other_txout != NULL);
      other_tx->txouts[i] = other_txout;
    }
  }

  return 0;
}

int free_txins(transaction_t *tx)
{
  assert(tx != NULL);
  if (tx->txin_count > 0 && tx->txins != NULL)
  {
    for (int i = 0; i < tx->txin_count; i++)
    {
      input_transaction_t *txin = tx->txins[i];
      assert(txin != NULL);
      free(txin);
    }

    free(tx->txins);
  }

  return 0;
}

int free_txouts(transaction_t *tx)
{
  assert(tx != NULL);
  if (tx->txout_count > 0 && tx->txouts != NULL)
  {
    for (int i = 0; i < tx->txout_count; i++)
    {
      output_transaction_t *txout = tx->txouts[i];
      assert(txout != NULL);
      free(txout);
    }

    free(tx->txouts);
  }

  return 0;
}

int free_transaction(transaction_t *tx)
{
  assert(tx != NULL);
  free_txins(tx);
  free_txouts(tx);
  free(tx);
  return 0;
}

int free_unspent_txouts(unspent_transaction_t *unspent_tx)
{
  assert(unspent_tx != NULL);
  if (unspent_tx->unspent_txout_count > 0 && unspent_tx->unspent_txouts != NULL)
  {
    for (int i = 0; i < unspent_tx->unspent_txout_count; i++)
    {
      unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[i];
      assert(unspent_txout != NULL);
      free(unspent_txout);
    }

    free(unspent_tx->unspent_txouts);
  }

  return 0;
}

int free_unspent_transaction(unspent_transaction_t *unspent_tx)
{
  assert(unspent_tx != NULL);
  free_unspent_txouts(unspent_tx);
  free(unspent_tx);
  return 0;
}
