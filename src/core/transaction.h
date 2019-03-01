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

#pragma once

#include <stdint.h>

#include <sodium.h>

#include "common/buffer.h"
#include "common/util.h"

#include "vulkan.pb-c.h"

#include "wallet/wallet.h"

/*
 * Transactions can contain multiple InputTXs and multiple OutputTXs.
 *
 * InputTXs are treated as sources of value, pooled together and then split apart into one or more OutputTXs
 * InputTXs reference a previous transaction hash where the value is coming from an earlier OutputTX (solidified in the blockchain)
 * InputTXs contain a signature of the InputTX header, as well as the public key that signed it.
 *   - The public key is converted into an Address to verify that the prev OutputTX was sent to the pubkey's address.
 *   - This "unlocks" the previous OutputTX to be used as this current InputTX.
 *   - The public key is used to verify the signature. (meaning the header has not been tampered.)
 *   - From this, we know that:
 *     - The person that is making this transaction owns the value designated by the transaction the InputTX(s) refer to.
 *     - The person confirms that this transaction should be taking place.
 *
 * Once an OutputTX is used as an InputTX, it is considered spent. (All value is used from a OutputTX when being used as input)
 * - If you don't want to spend everything from an InputTX, you can create a new OutputTX to send back to yourself as leftover-change.
 */

#ifdef __cplusplus
extern "C"
{
#endif

#define TXIN_HEADER_SIZE (HASH_SIZE + 4)
#define TXOUT_HEADER_SIZE (HASH_SIZE + 4)

#define MAX_NUM_TX_ENTRIES 1024

extern uint8_t zero_tx_hash[HASH_SIZE];

typedef struct InputTransaction
{
  // --- Header
  uint8_t transaction[HASH_SIZE]; // Previous tx hash/id
  uint32_t txout_index; // Referenced txout index in previous tx
  // ---

  uint8_t signature[crypto_sign_BYTES];
  uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
} input_transaction_t;

typedef struct OutputTransaction
{
  uint64_t amount;
  uint8_t address[ADDRESS_SIZE];
} output_transaction_t;

typedef struct Transaction
{
  uint8_t id[HASH_SIZE];
  uint8_t txin_count;
  uint8_t txout_count;
  input_transaction_t **txins;
  output_transaction_t **txouts;
} transaction_t;

typedef struct UnspentOutputTransaction
{
  uint64_t amount;
  uint8_t address[ADDRESS_SIZE];
  uint8_t spent;
} unspent_output_transaction_t;

typedef struct UnspentTransaction
{
  uint8_t id[HASH_SIZE];
  uint8_t coinbase;
  uint8_t unspent_txout_count;
  unspent_output_transaction_t **unspent_txouts;
} unspent_transaction_t;

typedef struct TransactionEntry
{
  uint8_t *address;
  uint64_t amount;
} transaction_entry_t;

typedef struct TransactionEntries
{
  uint16_t num_entries;
  transaction_entry_t entries[MAX_NUM_TX_ENTRIES];
} transaction_entries_t;

int sign_txin(input_transaction_t *txin, transaction_t *tx, uint8_t *public_key, uint8_t *secret_key);
int get_txin_header(uint8_t *header, input_transaction_t *txin);
int get_txout_header(uint8_t *header, output_transaction_t *txout);
uint32_t get_tx_sign_header_size(transaction_t *tx);
uint32_t get_tx_header_size(transaction_t *tx);
int get_tx_sign_header(uint8_t *header, transaction_t *tx);

int compare_transaction_hash(uint8_t *id, uint8_t *other_id);
int compare_transaction(transaction_t *transaction, transaction_t *other_transaction);

int valid_transaction(transaction_t *tx);
int is_generation_tx(transaction_t *tx);
int do_txins_reference_unspent_txouts(transaction_t *tx);

int compute_tx_id(uint8_t *header, transaction_t *tx);
int compute_self_tx_id(transaction_t *tx);

int serialize_txin(buffer_t *buffer, input_transaction_t *txin);
input_transaction_t* deserialize_txin(buffer_t *buffer);
int serialize_txout(buffer_t *buffer, output_transaction_t *txout);
output_transaction_t* deserialize_txout(buffer_t *buffer);
int serialize_transaction(buffer_t *buffer, transaction_t *tx);
transaction_t* deserialize_transaction(buffer_t *buffer);

int transaction_to_serialized(uint8_t **data, uint32_t *data_len, transaction_t *tx);
transaction_t* transaction_from_serialized(uint8_t *data, uint32_t data_len);

int serialize_unspent_txout(buffer_t *buffer, unspent_output_transaction_t *unspent_txout);
unspent_output_transaction_t* deserialize_unspent_txout(buffer_t *buffer);
int serialize_unspent_transaction(buffer_t *buffer, unspent_transaction_t *unspent_tx);
unspent_transaction_t* deserialize_unspent_transaction(buffer_t *buffer);

unspent_transaction_t* transaction_to_unspent_transaction(transaction_t *tx);
int unspent_transaction_to_serialized(uint8_t **data, uint32_t *data_len, unspent_transaction_t *unspent_tx);
unspent_transaction_t* unspent_transaction_from_serialized(uint8_t *data, uint32_t data_len);

input_transaction_t* make_txin(uint32_t block_height);
output_transaction_t* make_txout(uint8_t *address, uint64_t amount);
transaction_t* make_tx(PWallet *wallet, uint32_t block_height, uint64_t already_generated_coins, transaction_entries_t transaction_entries);
transaction_t* make_generation_tx(PWallet *wallet, uint32_t block_height, uint64_t already_generated_coins, uint64_t block_reward);

int free_transaction(transaction_t *tx);
int free_unspent_transaction(unspent_transaction_t *unspent_tx);

#ifdef __cplusplus
}
#endif
