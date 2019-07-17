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
#include <inttypes.h>

#include <sodium.h>

#include "common/buffer_iterator.h"
#include "common/buffer.h"
#include "common/logger.h"
#include "common/util.h"
#include "common/vec.h"

#include "blockchain.h"
#include "transaction.h"

#include "crypto/cryptoutil.h"
#include "crypto/sha256d.h"

#include "wallet/wallet.h"

static const uint8_t g_transaction_zero_hash[HASH_SIZE] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

transaction_t* make_transaction(void)
{
  transaction_t *tx = malloc(sizeof(transaction_t));
  assert(tx != NULL);
  tx->txin_count = 0;
  tx->txout_count = 0;
  tx->txins = NULL;
  tx->txouts = NULL;
  return tx;
}

input_transaction_t* make_txin(void)
{
  input_transaction_t *txin = malloc(sizeof(input_transaction_t));
  assert(txin != NULL);
  txin->txout_index = 0;
  return txin;
}

output_transaction_t* make_txout(void)
{
  output_transaction_t *txout = malloc(sizeof(output_transaction_t));
  assert(txout != NULL);
  txout->amount = 0;
  return txout;
}

unspent_transaction_t* make_unspent_transaction(void)
{
  unspent_transaction_t *unspent_tx = malloc(sizeof(unspent_transaction_t));
  assert(unspent_tx != NULL);
  unspent_tx->coinbase = 0;
  unspent_tx->unspent_txout_count = 0;
  unspent_tx->unspent_txouts = NULL;
  return unspent_tx;
}

unspent_output_transaction_t* make_unspent_txout(void)
{
  unspent_output_transaction_t *unspent_txout = malloc(sizeof(unspent_output_transaction_t));
  assert(unspent_txout != NULL);
  unspent_txout->amount = 0;
  unspent_txout->spent = 0;
  return unspent_txout;
}

/*
 * This function takes in:
 * - a single TXIN to sign for.
 * - a partially filled out TX that contains all the TXOUTs to sign for.
 * - public key for signature + address verification
 * - secret key to sign
 */
int sign_txin(input_transaction_t *txin, transaction_t *tx, uint8_t *public_key, uint8_t *secret_key)
{
  assert(txin != NULL);
  assert(tx != NULL);
  assert(public_key != NULL);
  assert(secret_key != NULL);

  uint32_t header_size = get_tx_sign_header_size(tx) + TXIN_HEADER_SIZE;
  uint8_t header[header_size];
  uint8_t hash[HASH_SIZE];

  get_txin_header(header, txin);
  get_tx_sign_header(header + TXIN_HEADER_SIZE, tx);

  crypto_hash_sha256d(hash, header, header_size);
  crypto_sign_detached(txin->signature, NULL, header, header_size, secret_key);

  memcpy(txin->public_key, public_key, crypto_sign_PUBLICKEYBYTES);
  return 0;
}

int validate_txin_signature(transaction_t *tx, input_transaction_t *txin)
{
  assert(tx != NULL);
  assert(txin != NULL);

  uint32_t header_size = get_tx_sign_header_size(tx) + TXIN_HEADER_SIZE;
  uint8_t header[header_size];

  get_txin_header(header, txin);
  get_tx_sign_header(header + TXIN_HEADER_SIZE, tx);

  if (crypto_sign_verify_detached(txin->signature, header, header_size, txin->public_key) != 0)
  {
    char *tx_hash_str = bin2hex(tx->id, HASH_SIZE);
    char *public_key_str = bin2hex(txin->public_key, crypto_sign_PUBLICKEYBYTES);
    LOG_ERROR("Failed to verify signature for transaction: %s with public key: %s!", tx_hash_str, public_key_str);
    free(tx_hash_str);
    free(public_key_str);
    return 1;
  }

  return 0;
}

int validate_tx_signatures(transaction_t *tx)
{
  assert(tx != NULL);
  for (uint32_t txin_index = 0; txin_index < tx->txin_count; txin_index++)
  {
    input_transaction_t *txin = tx->txins[txin_index];
    assert(txin != NULL);

    if (validate_txin_signature(tx, txin))
    {
      return 1;
    }
  }

  return 0;
}

void get_txin_header(uint8_t *header, input_transaction_t *txin)
{
  assert(header != NULL);
  assert(txin != NULL);

  memcpy(header, txin->transaction, HASH_SIZE);
  memcpy(header + HASH_SIZE, &txin->txout_index, 4);
}

void get_txout_header(uint8_t *header, output_transaction_t *txout)
{
  assert(header != NULL);
  assert(txout != NULL);

  memcpy(header, &txout->amount, 4);
  memcpy(header, txout->address, ADDRESS_SIZE);
}

uint32_t get_tx_header_size(transaction_t *tx)
{
  assert(tx != NULL);
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
  assert(tx != NULL);
  uint32_t txout_header_sizes = TXOUT_HEADER_SIZE * tx->txout_count;
  return txout_header_sizes;
}

void get_tx_sign_header(uint8_t *header, transaction_t *tx)
{
  assert(header != NULL);
  assert(tx != NULL);

  for (uint32_t i = 0; i < tx->txout_count; i++)
  {
    output_transaction_t *txout = tx->txouts[i];
    assert(txout != NULL);

    get_txout_header(header + (TXOUT_HEADER_SIZE * i), txout);
  }
}

int compare_transaction_hash(uint8_t *id, uint8_t *other_id)
{
  assert(id != NULL);
  assert(other_id != NULL);
  return memcmp(id, other_id, HASH_SIZE) == 0;
}

int compare_transaction(transaction_t *transaction, transaction_t *other_transaction)
{
  assert(transaction != NULL);
  assert(other_transaction != NULL);
  return compare_transaction_hash(transaction->id, other_transaction->id);
}

void print_txin(uint8_t txin_index, input_transaction_t *txin)
{
  assert(txin != NULL);
  printf("Txin %u:\n", txin_index);

  char *previous_tx_str = bin2hex(txin->transaction, HASH_SIZE);
  printf("Previous Tx: %s\n", previous_tx_str);
  free(previous_tx_str);

  printf("Index: %u\n", txin->txout_index);

  char *signature_str = bin2hex(txin->signature, crypto_sign_BYTES);
  printf("Signature: %s\n", signature_str);
  free(signature_str);

  char *public_key_str = bin2hex(txin->public_key, crypto_sign_PUBLICKEYBYTES);
  printf("Public Key: %s\n", public_key_str);
  free(public_key_str);
}

void print_txout(uint8_t txout_index, output_transaction_t *txout)
{
  assert(txout != NULL);
  printf("Txout %u:\n", txout_index);
  printf("Amount: %" PRIu64 "\n", txout->amount);

  char *address_str = bin2hex(txout->address, ADDRESS_SIZE);
  printf("Address: %s\n", address_str);
  free(address_str);
}

void print_transaction(transaction_t *tx)
{
  assert(tx != NULL);
  printf("Transaction:\n");

  char *tx_id_str = bin2hex(tx->id, HASH_SIZE);
  printf("Id: %s\n", tx_id_str);
  free(tx_id_str);

  printf("Txin Count: %u\n", tx->txin_count);
  printf("Txout Count: %u\n", tx->txout_count);
  printf("\n");

  // print txins
  for (uint32_t i = 0; i < tx->txin_count; i++)
  {
    input_transaction_t *txin = tx->txins[i];
    assert(txin != NULL);

    print_txin(i, txin);
    printf("\n");
  }

  // print txouts
  for (uint32_t i = 0; i < tx->txout_count; i++)
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
  assert(tx != NULL);
  if (tx->txout_count == 0 || tx->txouts == NULL)
  {
    return 0;
  }

  uint32_t tx_header_size = get_tx_header_size(tx);
  if (tx_header_size > MAX_TX_SIZE)
  {
    LOG_DEBUG("Transaction has too big header blob size: %u!", tx_header_size);
    return 0;
  }

  // check signatures
  if (validate_tx_signatures(tx))
  {
    return 0;
  }

  if (is_generation_tx(tx))
  {
    return 1;
  }

  // check txins and txouts
  if (do_txins_reference_unspent_txouts(tx) == 0)
  {
    return 0;
  }

  return 1;
}

int do_txins_reference_unspent_txouts(transaction_t *tx)
{
  assert(tx != NULL);

  uint32_t valid_txins = 0;
  uint64_t input_money = 0;
  uint64_t required_money = 0;

  for (uint32_t i = 0; i < tx->txin_count; i++)
  {
    input_transaction_t *txin = tx->txins[i];
    assert(txin != NULL);

    unspent_transaction_t *unspent_tx = get_unspent_tx_from_index(txin->transaction);
    if (unspent_tx != NULL)
    {
      if (((unspent_tx->unspent_txout_count - 1) < txin->txout_index) ||
          (unspent_tx->unspent_txouts[txin->txout_index] == NULL))
      {
        char *tx_hash_str = bin2hex(unspent_tx->id, HASH_SIZE);
        LOG_ERROR("Failed to validate txin referencing invalid unspent tx: %s with txout at index: %u!", tx_hash_str, txin->txout_index);
        free(tx_hash_str);
        return 0;
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

  for (uint32_t i = 0; i < tx->txout_count; i++)
  {
    output_transaction_t *txout = tx->txouts[i];
    assert(txout != NULL);

    if (valid_address(txout->address) == 0)
    {
      char *tx_hash_str = bin2hex(tx->id, HASH_SIZE);
      LOG_ERROR("Failed to validate txin: %s invalid txout address at index: %u", tx_hash_str, i);
      free(tx_hash_str);
      return 0;
    }

    required_money += txout->amount;
  }

  return (valid_txins == tx->txin_count) && (input_money == required_money);
}

int is_generation_tx(transaction_t *tx)
{
  assert(tx != NULL);
  return (tx->txin_count == 1 && tx->txout_count == 1 && compare_transaction_hash(tx->txins[0]->transaction, (uint8_t*)g_transaction_zero_hash));
}

int compute_tx_id(uint8_t *tx_id, transaction_t *tx)
{
  assert(tx != NULL);
  uint32_t tx_header_size = get_tx_header_size(tx);
  assert(tx_header_size > 0);

  buffer_t *buffer = buffer_init_size(0, tx_header_size);
  serialize_transaction_header(buffer, tx);

  uint8_t header[tx_header_size];
  memcpy(header, buffer->data, tx_header_size);

  buffer_free(buffer);
  crypto_hash_sha256d(tx_id, header, tx_header_size);
  return 0;
}

int compute_self_tx_id(transaction_t *tx)
{
  assert(tx != NULL);
  compute_tx_id(tx->id, tx);
  return 0;
}

int serialize_txin_header(buffer_t *buffer, input_transaction_t *txin)
{
  assert(buffer != NULL);
  assert(txin != NULL);

  buffer_write(buffer, txin->transaction, HASH_SIZE);
  buffer_write_uint32(buffer, txin->txout_index);
  return 0;
}

int serialize_txin(buffer_t *buffer, input_transaction_t *txin)
{
  assert(buffer != NULL);
  assert(txin != NULL);

  buffer_write_bytes(buffer, txin->transaction, HASH_SIZE);
  buffer_write_uint32(buffer, txin->txout_index);

  buffer_write_bytes(buffer, txin->signature, crypto_sign_BYTES);
  buffer_write_bytes(buffer, txin->public_key, crypto_sign_PUBLICKEYBYTES);
  return 0;
}

int deserialize_txin(buffer_iterator_t *buffer_iterator, input_transaction_t **txin_out)
{
  assert(buffer_iterator != NULL);
  input_transaction_t *txin = make_txin();
  uint8_t *prev_tx_id = NULL;
  if (buffer_read_bytes(buffer_iterator, &prev_tx_id))
  {
    free(txin);
    return 1;
  }

  memcpy(txin->transaction, prev_tx_id, HASH_SIZE);
  free(prev_tx_id);

  txin->txout_index = 0;
  if (buffer_read_uint32(buffer_iterator, &txin->txout_index))
  {
    free(txin);
    return 1;
  }

  uint8_t *signature = NULL;
  if (buffer_read_bytes(buffer_iterator, &signature))
  {
    free(txin);
    return 1;
  }

  memcpy(txin->signature, signature, crypto_sign_BYTES);
  free(signature);

  uint8_t *public_key = NULL;
  if (buffer_read_bytes(buffer_iterator, &public_key))
  {
    free(txin);
    return 1;
  }

  memcpy(txin->public_key, public_key, crypto_sign_PUBLICKEYBYTES);
  free(public_key);

  *txin_out = txin;
  return 0;
}

int serialize_txout_header(buffer_t *buffer, output_transaction_t *txout)
{
  assert(buffer != NULL);
  assert(txout != NULL);

  buffer_write_uint64(buffer, txout->amount);
  buffer_write(buffer, txout->address, ADDRESS_SIZE);
  return 0;
}

int serialize_txout(buffer_t *buffer, output_transaction_t *txout)
{
  assert(buffer != NULL);
  assert(txout != NULL);

  buffer_write_uint64(buffer, txout->amount);
  buffer_write_bytes(buffer, txout->address, ADDRESS_SIZE);
  return 0;
}

int deserialize_txout(buffer_iterator_t *buffer_iterator, output_transaction_t **txout_out)
{
  assert(buffer_iterator != NULL);
  output_transaction_t *txout = make_txout();
  txout->amount = 0;
  if (buffer_read_uint64(buffer_iterator, &txout->amount))
  {
    free(txout);
    return 1;
  }

  uint8_t *address = NULL;
  if (buffer_read_bytes(buffer_iterator, &address))
  {
    free(txout);
    return 1;
  }

  memcpy(txout->address, address, ADDRESS_SIZE);
  free(address);

  *txout_out = txout;
  return 0;
}

int serialize_transaction_header(buffer_t *buffer, transaction_t *tx)
{
  assert(buffer != NULL);
  assert(tx != NULL);

  // write txins
  for (uint32_t i = 0; i < tx->txin_count; i++)
  {
    input_transaction_t *txin = tx->txins[i];
    assert(txin != NULL);

    if (serialize_txin_header(buffer, txin))
    {
      return 1;
    }
  }

  // write txouts
  for (uint32_t i = 0; i < tx->txout_count; i++)
  {
    output_transaction_t *txout = tx->txouts[i];
    assert(txout != NULL);

    if (serialize_txout_header(buffer, txout))
    {
      return 1;
    }
  }

  return 0;
}

int serialize_transaction(buffer_t *buffer, transaction_t *tx)
{
  assert(buffer != NULL);
  assert(tx != NULL);

  buffer_write_bytes(buffer, tx->id, HASH_SIZE);
  buffer_write_uint32(buffer, tx->txin_count);
  buffer_write_uint32(buffer, tx->txout_count);

  // write txins
  for (uint32_t i = 0; i < tx->txin_count; i++)
  {
    input_transaction_t *txin = tx->txins[i];
    assert(txin != NULL);

    if (serialize_txin(buffer, txin))
    {
      return 1;
    }
  }

  // write txouts
  for (uint32_t i = 0; i < tx->txout_count; i++)
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

int deserialize_transaction(buffer_iterator_t *buffer_iterator, transaction_t **tx_out)
{
  assert(buffer_iterator != NULL);
  transaction_t *tx = make_transaction();
  uint8_t *id = NULL;
  if (buffer_read_bytes(buffer_iterator, &id))
  {
    goto deserialize_fail;
  }

  memcpy(tx->id, id, HASH_SIZE);
  free(id);

  uint32_t txin_count = 0;
  if (buffer_read_uint32(buffer_iterator, &txin_count))
  {
    goto deserialize_fail;
  }

  uint32_t txout_count = 0;
  if (buffer_read_uint32(buffer_iterator, &txout_count))
  {
    goto deserialize_fail;
  }

  // read txins
  for (uint32_t i = 0; i < txin_count; i++)
  {
    input_transaction_t *txin = NULL;
    if (deserialize_txin(buffer_iterator, &txin))
    {
      goto deserialize_fail;
    }

    tx->txin_count++;
    assert(i == tx->txin_count - 1);

    tx->txins = realloc(tx->txins, sizeof(input_transaction_t) * tx->txin_count);
    assert(tx->txins != NULL);

    tx->txins[i] = txin;
  }

  // read txouts
  for (uint32_t i = 0; i < txout_count; i++)
  {
    output_transaction_t *txout = NULL;
    if (deserialize_txout(buffer_iterator, &txout))
    {
      goto deserialize_fail;
    }

    tx->txout_count++;
    assert(i == tx->txout_count - 1);

    tx->txouts = realloc(tx->txouts, sizeof(output_transaction_t) * tx->txout_count);
    assert(tx->txouts != NULL);

    tx->txouts[i] = txout;
  }

  *tx_out = tx;
  return 0;

deserialize_fail:
  free_transaction(tx);
  return 1;
}

int transaction_to_serialized(uint8_t **data, uint32_t *data_len, transaction_t *tx)
{
  assert(tx != NULL);
  buffer_t *buffer = buffer_init();
  if (serialize_transaction(buffer, tx))
  {
    buffer_free(buffer);
    return 1;
  }

  uint32_t raw_data_len = buffer_get_size(buffer);
  uint8_t *raw_data = malloc(raw_data_len);
  assert(raw_data != NULL);
  memcpy(raw_data, buffer->data, raw_data_len);

  *data_len = raw_data_len;
  *data = raw_data;

  buffer_free(buffer);
  return 0;
}

transaction_t* transaction_from_serialized(uint8_t *data, uint32_t data_len)
{
  assert(data != NULL);
  buffer_t *buffer = buffer_init_data(0, (const uint8_t*)data, data_len);
  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);

  transaction_t *tx = NULL;
  if (deserialize_transaction(buffer_iterator, &tx))
  {
    buffer_iterator_free(buffer_iterator);
    buffer_free(buffer);
    return NULL;
  }

  buffer_iterator_free(buffer_iterator);
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

int deserialize_unspent_txout(buffer_iterator_t *buffer_iterator, unspent_output_transaction_t **unspent_txout_out)
{
  assert(buffer_iterator != NULL);
  unspent_output_transaction_t *unspent_txout = make_unspent_txout();
  if (buffer_read_uint64(buffer_iterator, &unspent_txout->amount))
  {
    free(unspent_txout);
    return 1;
  }

  uint8_t *address = NULL;
  if (buffer_read_bytes(buffer_iterator, &address))
  {
    free(unspent_txout);
    return 1;
  }

  memcpy(unspent_txout->address, address, ADDRESS_SIZE);
  free(address);

  unspent_txout->spent = 0;
  if (buffer_read_uint8(buffer_iterator, &unspent_txout->spent))
  {
    free(unspent_txout);
    return 1;
  }

  *unspent_txout_out = unspent_txout;
  return 0;
}

int serialize_unspent_transaction(buffer_t *buffer, unspent_transaction_t *unspent_tx)
{
  assert(buffer != NULL);
  assert(unspent_tx != NULL);

  buffer_write_bytes(buffer, unspent_tx->id, HASH_SIZE);
  buffer_write_uint8(buffer, unspent_tx->coinbase);
  buffer_write_uint32(buffer, unspent_tx->unspent_txout_count);

  // write unspent txouts
  for (uint32_t i = 0; i < unspent_tx->unspent_txout_count; i++)
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

int deserialize_unspent_transaction(buffer_iterator_t *buffer_iterator, unspent_transaction_t **unspent_tx_out)
{
  assert(buffer_iterator != NULL);
  unspent_transaction_t *unspent_tx = make_unspent_transaction();
  uint8_t *id = NULL;
  if (buffer_read_bytes(buffer_iterator, &id))
  {
    goto unspent_tx_deserialize_fail;
  }

  memcpy(unspent_tx->id, id, HASH_SIZE);
  free(id);

  unspent_tx->coinbase = 0;
  if (buffer_read_uint8(buffer_iterator, &unspent_tx->coinbase))
  {
    goto unspent_tx_deserialize_fail;
  }

  uint32_t unspent_txout_count = 0;
  if (buffer_read_uint32(buffer_iterator, &unspent_txout_count))
  {
    goto unspent_tx_deserialize_fail;
  }

  // read unspent txouts
  for (uint32_t i = 0; i < unspent_txout_count; i++)
  {
    unspent_output_transaction_t *unspent_txout = NULL;
    if (deserialize_unspent_txout(buffer_iterator, &unspent_txout))
    {
      goto unspent_tx_deserialize_fail;
    }

    unspent_tx->unspent_txout_count++;
    assert(i == unspent_tx->unspent_txout_count - 1);

    unspent_tx->unspent_txouts = realloc(unspent_tx->unspent_txouts, sizeof(unspent_output_transaction_t) * unspent_tx->unspent_txout_count);
    assert(unspent_tx->unspent_txouts != NULL);

    unspent_tx->unspent_txouts[i] = unspent_txout;
  }

  *unspent_tx_out = unspent_tx;
  return 0;

unspent_tx_deserialize_fail:
  free_unspent_transaction(unspent_tx);
  return 1;
}

unspent_output_transaction_t* txout_to_unspent_txout(output_transaction_t *txout)
{
  assert(txout != NULL);
  unspent_output_transaction_t *unspent_txout = make_unspent_txout();
  unspent_txout->amount = txout->amount;
  memcpy(unspent_txout->address, txout->address, ADDRESS_SIZE);
  unspent_txout->spent = 0;
  return unspent_txout;
}

unspent_transaction_t* transaction_to_unspent_transaction(transaction_t *tx)
{
  assert(tx != NULL);
  unspent_transaction_t *unspent_tx = make_unspent_transaction();
  memcpy(unspent_tx->id, tx->id, HASH_SIZE);

  unspent_tx->coinbase = is_generation_tx(tx);
  unspent_tx->unspent_txout_count = tx->txout_count;

  unspent_tx->unspent_txouts = malloc(sizeof(unspent_output_transaction_t) * tx->txout_count);
  assert(unspent_tx->unspent_txouts != NULL);

  for (uint32_t i = 0; i < unspent_tx->unspent_txout_count; i++)
  {
    output_transaction_t *txout = tx->txouts[i];
    assert(txout != NULL);

    unspent_output_transaction_t *unspent_txout = txout_to_unspent_txout(txout);
    assert(unspent_txout != NULL);

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
    buffer_free(buffer);
    return 1;
  }

  *data_len = buffer_get_size(buffer);
  *data = malloc(*data_len);
  assert(*data != NULL);
  memcpy(*data, buffer->data, *data_len);
  buffer_free(buffer);
  return 0;
}

unspent_transaction_t* unspent_transaction_from_serialized(uint8_t *data, uint32_t data_len)
{
  assert(data != NULL);
  assert(data_len > 0);
  buffer_t *buffer = buffer_init_data(0, (const uint8_t*)data, data_len);
  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);

  unspent_transaction_t *unspent_tx = NULL;
  if (deserialize_unspent_transaction(buffer_iterator, &unspent_tx))
  {
    buffer_iterator_free(buffer_iterator);
    buffer_free(buffer);
    return NULL;
  }

  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);
  return unspent_tx;
}

int get_unspent_txouts_from_unspent_tx(unspent_transaction_t *unspent_tx, vec_void_t *unspent_txouts, uint32_t *num_unspent_txouts)
{
  assert(unspent_tx != NULL);
  assert(unspent_txouts != NULL);

  for (uint32_t i = 0; i < unspent_tx->unspent_txout_count; i++)
  {
    unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[i];
    assert(unspent_txout != NULL);

    if (unspent_txout->spent == 1)
    {
      continue;
    }

    assert(vec_push(unspent_txouts, unspent_txout) == 0);
    *num_unspent_txouts += 1;
  }

  return 0;
}

int add_txin_to_transaction(transaction_t *tx, input_transaction_t *txin, uint32_t txin_index)
{
  assert(tx != NULL);
  assert(txin != NULL);

  tx->txin_count++;
  assert(txin_index == tx->txin_count - 1);

  tx->txins = realloc(tx->txins, sizeof(input_transaction_t) * tx->txin_count);
  assert(tx->txins != NULL);

  tx->txins[txin_index] = txin;
  return 0;
}

int add_txout_to_transaction(transaction_t *tx, output_transaction_t *txout, uint32_t txout_index)
{
  assert(tx != NULL);
  assert(txout != NULL);

  tx->txout_count++;
  assert(txout_index == tx->txout_count - 1);

  tx->txouts = realloc(tx->txouts, sizeof(output_transaction_t) * tx->txout_count);
  assert(tx->txouts != NULL);

  tx->txouts[txout_index] = txout;
  return 0;
}

int copy_txin(input_transaction_t *txin, input_transaction_t *other_txin)
{
  assert(txin != NULL);
  assert(other_txin != NULL);

  memcpy(other_txin->transaction, txin->transaction, HASH_SIZE);
  other_txin->txout_index = txin->txout_index;

  memcpy(other_txin->signature, txin->signature, HASH_SIZE);
  memcpy(other_txin->public_key, txin->public_key, HASH_SIZE);
  return 0;
}

int copy_txout(output_transaction_t *txout, output_transaction_t *other_txout)
{
  assert(txout != NULL);
  assert(other_txout != NULL);

  other_txout->amount = txout->amount;
  memcpy(other_txout->address, txout->address, HASH_SIZE);
  return 0;
}

int copy_transaction(transaction_t *tx, transaction_t *other_tx)
{
  assert(tx != NULL);
  assert(other_tx != NULL);

  // free the txins and txouts for the transaction we are copying to...
  free_txins(other_tx);
  free_txouts(other_tx);

  memcpy(other_tx->id, tx->id, HASH_SIZE);
  if ((tx->txin_count > 0 && tx->txins != NULL) && (tx->txout_count > 0 && tx->txouts != NULL))
  {
    // copy the txins
    for (uint32_t i = 0; i < tx->txin_count; i++)
    {
      input_transaction_t *txin = tx->txins[i];
      assert(txin != NULL);

      input_transaction_t *other_txin = malloc(sizeof(input_transaction_t));
      assert(other_txin != NULL);
      if (copy_txin(txin, other_txin))
      {
        return 1;
      }

      assert(other_txin != NULL);
      other_tx->txin_count++;
      assert(i == other_tx->txin_count - 1);

      other_tx->txins = realloc(other_tx->txins, sizeof(input_transaction_t) * other_tx->txin_count);
      assert(other_tx->txins != NULL);

      other_tx->txins[i] = other_txin;
    }

    // copy the txouts
    for (uint32_t i = 0; i < tx->txout_count; i++)
    {
      output_transaction_t *txout = tx->txouts[i];
      assert(txout != NULL);

      output_transaction_t *other_txout = malloc(sizeof(output_transaction_t));
      assert(other_txout != NULL);
      if (copy_txout(txout, other_txout))
      {
        return 1;
      }

      assert(other_txout != NULL);
      other_tx->txout_count++;
      assert(i == other_tx->txout_count - 1);

      other_tx->txouts = realloc(other_tx->txouts, sizeof(output_transaction_t) * other_tx->txout_count);
      assert(other_tx->txouts != NULL);

      other_tx->txouts[i] = other_txout;
    }
  }

  return 0;
}

void free_txins(transaction_t *tx)
{
  assert(tx != NULL);
  if (tx->txin_count > 0 && tx->txins != NULL)
  {
    for (uint32_t i = 0; i < tx->txin_count; i++)
    {
      input_transaction_t *txin = tx->txins[i];
      assert(txin != NULL);
      free(txin);
    }

    free(tx->txins);
    tx->txins = NULL;
  }
}

void free_txouts(transaction_t *tx)
{
  assert(tx != NULL);
  if (tx->txout_count > 0 && tx->txouts != NULL)
  {
    for (uint32_t i = 0; i < tx->txout_count; i++)
    {
      output_transaction_t *txout = tx->txouts[i];
      assert(txout != NULL);
      free(txout);
    }

    free(tx->txouts);
    tx->txouts = NULL;
  }
}

void free_transaction(transaction_t *tx)
{
  assert(tx != NULL);
  free_txins(tx);
  free_txouts(tx);
  free(tx);
}

void free_unspent_txouts(unspent_transaction_t *unspent_tx)
{
  assert(unspent_tx != NULL);
  if (unspent_tx->unspent_txout_count > 0 && unspent_tx->unspent_txouts != NULL)
  {
    for (uint32_t i = 0; i < unspent_tx->unspent_txout_count; i++)
    {
      unspent_output_transaction_t *unspent_txout = unspent_tx->unspent_txouts[i];
      assert(unspent_txout != NULL);
      free(unspent_txout);
    }

    free(unspent_tx->unspent_txouts);
    unspent_tx->unspent_txouts = NULL;
  }
}

void free_unspent_transaction(unspent_transaction_t *unspent_tx)
{
  assert(unspent_tx != NULL);
  free_unspent_txouts(unspent_tx);
  free(unspent_tx);
}
