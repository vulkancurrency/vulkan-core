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

#include "common/buffer_iterator.h"
#include "common/buffer.h"
#include "common/util.h"
#include "common/vec.h"
#include "common/vulkan.h"

#include "crypto/cryptoutil.h"

#include "wallet/wallet.h"

VULKAN_BEGIN_DECL

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

#define TXIN_HEADER_SIZE (HASH_SIZE + 4)
#define TXOUT_HEADER_SIZE (ADDRESS_SIZE + 8)

#define MAX_NUM_TX_ENTRIES 1024

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
  uint32_t txin_count;
  uint32_t txout_count;
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
  uint32_t unspent_txout_count;
  unspent_output_transaction_t **unspent_txouts;
} unspent_transaction_t;

VULKAN_API transaction_t* make_transaction(void);
VULKAN_API input_transaction_t* make_txin(void);
VULKAN_API output_transaction_t* make_txout(void);
VULKAN_API unspent_output_transaction_t* make_unspent_txout(void);
VULKAN_API unspent_transaction_t* make_unspent_transaction(void);

VULKAN_API int sign_txin(input_transaction_t *txin, transaction_t *tx, uint8_t *public_key, uint8_t *secret_key);
VULKAN_API int validate_txin_signature(transaction_t *tx, input_transaction_t *txin);
VULKAN_API int validate_tx_signatures(transaction_t *tx);
VULKAN_API void get_txin_header(uint8_t *header, input_transaction_t *txin);
VULKAN_API void get_txout_header(uint8_t *header, output_transaction_t *txout);
VULKAN_API uint32_t get_tx_sign_header_size(transaction_t *tx);
VULKAN_API uint32_t get_tx_header_size(transaction_t *tx);
VULKAN_API void get_tx_sign_header(uint8_t *header, transaction_t *tx);

VULKAN_API int compare_txin(input_transaction_t *txin, input_transaction_t *other_txin);
VULKAN_API int compare_txout(output_transaction_t *txout, output_transaction_t *other_txout);
VULKAN_API int compare_transaction_txins(transaction_t *transaction, transaction_t *other_transaction);
VULKAN_API int compare_transaction_txouts(transaction_t *transaction, transaction_t *other_transaction);
VULKAN_API int compare_transaction(transaction_t *transaction, transaction_t *other_transaction);

VULKAN_API void print_txin(uint8_t txin_index, input_transaction_t *txin);
VULKAN_API void print_txout(uint8_t txout_index, output_transaction_t *txout);
VULKAN_API void print_transaction(transaction_t *tx);

VULKAN_API int valid_transaction(transaction_t *tx);
VULKAN_API int is_coinbase_tx(transaction_t *tx);
VULKAN_API int do_txins_reference_unspent_txouts(transaction_t *tx);

VULKAN_API int compute_tx_id(uint8_t *tx_id, transaction_t *tx);
VULKAN_API int compute_self_tx_id(transaction_t *tx);

VULKAN_API int serialize_txin_header(buffer_t *buffer, input_transaction_t *txin);
VULKAN_API int serialize_txin(buffer_t *buffer, input_transaction_t *txin);
VULKAN_API int deserialize_txin(buffer_iterator_t *buffer_iterator, input_transaction_t **txin_out);

VULKAN_API int serialize_txout_header(buffer_t *buffer, output_transaction_t *txout);
VULKAN_API int serialize_txout(buffer_t *buffer, output_transaction_t *txout);
VULKAN_API int deserialize_txout(buffer_iterator_t *buffer_iterator, output_transaction_t **txout_out);

VULKAN_API int serialize_transaction_header(buffer_t *buffer, transaction_t *tx);
VULKAN_API int serialize_transaction(buffer_t *buffer, transaction_t *tx);
VULKAN_API int deserialize_transaction(buffer_iterator_t *buffer_iterator, transaction_t **tx_out);

VULKAN_API int transaction_to_serialized(uint8_t **data, uint32_t *data_len, transaction_t *tx);
VULKAN_API transaction_t* transaction_from_serialized(uint8_t *data, uint32_t data_len);

VULKAN_API int serialize_unspent_txout(buffer_t *buffer, unspent_output_transaction_t *unspent_txout);
VULKAN_API int deserialize_unspent_txout(buffer_iterator_t *buffer_iterator, unspent_output_transaction_t **unspent_txout_out);

VULKAN_API int serialize_unspent_transaction(buffer_t *buffer, unspent_transaction_t *unspent_tx);
VULKAN_API int deserialize_unspent_transaction(buffer_iterator_t *buffer_iterator, unspent_transaction_t **unspent_tx_out);

VULKAN_API unspent_output_transaction_t* txout_to_unspent_txout(output_transaction_t *txout);
VULKAN_API unspent_transaction_t* transaction_to_unspent_transaction(transaction_t *tx);
VULKAN_API int unspent_transaction_to_serialized(uint8_t **data, uint32_t *data_len, unspent_transaction_t *unspent_tx);
VULKAN_API unspent_transaction_t* unspent_transaction_from_serialized(uint8_t *data, uint32_t data_len);
VULKAN_API int get_unspent_txouts_from_unspent_tx(unspent_transaction_t *unspent_tx, vec_void_t *unspent_txouts, uint32_t *num_unspent_txouts);

VULKAN_API int add_txin_to_transaction(transaction_t *tx, input_transaction_t *txin, uint32_t txin_index);
VULKAN_API int add_txout_to_transaction(transaction_t *tx, output_transaction_t *txout, uint32_t txout_index);

VULKAN_API int copy_txin(input_transaction_t *txin, input_transaction_t *other_txin);
VULKAN_API int copy_txout(output_transaction_t *txout, output_transaction_t *other_txout);
VULKAN_API int copy_transaction(transaction_t *tx, transaction_t *other_tx);

VULKAN_API void free_txins(transaction_t *tx);
VULKAN_API void free_txouts(transaction_t *tx);
VULKAN_API void free_transaction(transaction_t *tx);

VULKAN_API void free_unspent_txouts(unspent_transaction_t *unspent_tx);
VULKAN_API void free_unspent_transaction(unspent_transaction_t *unspent_tx);

VULKAN_END_DECL
