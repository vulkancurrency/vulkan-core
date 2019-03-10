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
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sodium.h>

#include <rocksdb/c.h>

#include "common/buffer.h"
#include "common/util.h"

#include "core/blockchain.h"
#include "core/blockchainparams.h"

#include "crypto/sha256d.h"

#include "wallet/wallet.h"

static const char *g_wallet_filename = NULL;

wallet_t* make_wallet(void)
{
  wallet_t *wallet = malloc(sizeof(wallet));
  wallet->balance = 0;
  return wallet;
}

int free_wallet(wallet_t *wallet)
{
  assert(wallet != NULL);
  free(wallet);
  return 0;
}

int serialize_wallet(buffer_t *buffer, wallet_t *wallet)
{
  assert(buffer != NULL);
  assert(wallet != NULL);

  buffer_write_bytes(buffer, wallet->secret_key, crypto_sign_SECRETKEYBYTES);
  buffer_write_bytes(buffer, wallet->public_key, crypto_sign_PUBLICKEYBYTES);
  buffer_write_bytes(buffer, wallet->address, ADDRESS_SIZE);
  buffer_write_uint64(buffer, wallet->balance);

  return 0;
}

wallet_t* deserialize_wallet(buffer_t *buffer)
{
  assert(buffer != NULL);

  wallet_t *wallet = make_wallet();

  uint8_t *secret_key = buffer_read_bytes(buffer);
  memcpy(&wallet->secret_key, secret_key, crypto_sign_SECRETKEYBYTES);

  uint8_t *public_key = buffer_read_bytes(buffer);
  memcpy(&wallet->public_key, public_key, crypto_sign_PUBLICKEYBYTES);

  uint8_t *address = buffer_read_bytes(buffer);
  memcpy(&wallet->address, address, ADDRESS_SIZE);

  wallet->balance = buffer_read_uint64(buffer);

  free(secret_key);
  free(public_key);
  free(address);

  return wallet;
}

/*
 * open_wallet()
 * Opens a LevelDB instance for the wallet
 */
rocksdb_t *open_wallet(const char *wallet_filename, char *err)
{
  g_wallet_filename = wallet_filename;

  rocksdb_t *db;
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(options, 1);

  return rocksdb_open(options, wallet_filename, &err);
}

int new_wallet(const char *wallet_filename)
{
  // Open DB

  char *err = NULL;
  rocksdb_t *db = open_wallet(wallet_filename, err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not open wallet\n");
    return 1;
  }

  rocksdb_free(err);
  err = NULL;

  // ----

  size_t read_len;
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  char *initialized = rocksdb_get(db, roptions, "0", 1, &read_len, &err);

  if (initialized != NULL)
  {
    rocksdb_free(initialized);
    fprintf(stderr, "Already initialized.\n");
    return 1;
  }

  rocksdb_free(err);

  // ----

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  unsigned char seed[crypto_sign_SEEDBYTES];
  unsigned char address[ADDRESS_SIZE];

  crypto_sign_keypair(pk, sk);
  crypto_sign_ed25519_sk_to_seed(seed, sk);
  public_key_to_address(address, pk);

  // ---

  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();

  wallet_t *wallet = make_wallet();
  memcpy(&wallet->secret_key, &sk, crypto_sign_SECRETKEYBYTES);
  memcpy(&wallet->public_key, &pk, crypto_sign_PUBLICKEYBYTES);
  memcpy(&wallet->address, &address, ADDRESS_SIZE);
  wallet->balance = 0;

  buffer_t *buffer = buffer_init();
  serialize_wallet(buffer, wallet);

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  rocksdb_put(db, woptions, "0", 1, (char*)data, data_len, &err);
  buffer_free(buffer);
  free_wallet(wallet);

  if (err != NULL)
  {
    fprintf(stderr, "Could not write to wallet database\n");
    return 1;
  }

  rocksdb_free(err);
  err = NULL;

  // Close DB
  rocksdb_close(db);
  return 0;
}

wallet_t *get_wallet(void)
{
  char *err = NULL;
  rocksdb_t *db = open_wallet(g_wallet_filename, err);

  if (err != NULL)
  {
    fprintf(stderr, "Could not open wallet database\n");
    rocksdb_free(err);
  }

  size_t read_len;
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *wallet_data = (uint8_t*)rocksdb_get(db, roptions, "0", 1, &read_len, &err);

  if (err != NULL || wallet_data == NULL)
  {
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    return NULL;
  }

  buffer_t *buffer = buffer_init_data(0, wallet_data, read_len);
  wallet_t *wallet = deserialize_wallet(buffer);
  buffer_free(buffer);

  rocksdb_free(wallet_data);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);

  rocksdb_close(db);
  return wallet;
}

void print_wallet(wallet_t *wallet)
{
  int public_address_len = (ADDRESS_SIZE * 2) + 1;
  char public_address[public_address_len];

  for (int i = 0; i < ADDRESS_SIZE; i++)
  {
    sprintf(&public_address[i*2], "%02x", (int) wallet->address[i]);
  }

  uint64_t balance = get_balance_for_address(wallet->address) / COIN;

  printf("Public Address: %s\n", public_address);
  printf("Balance: %llu\n", balance);
}

int compare_addresses(uint8_t *address, uint8_t *other_address)
{
  return memcmp(address, other_address, ADDRESS_SIZE) == 0;
}

int public_key_to_address(uint8_t *address, uint8_t *pk)
{
  uint8_t address_id = MAINNET_ADDRESS_ID;
  memcpy(address, &address_id, sizeof(uint8_t) * 1);
  crypto_hash_sha256d(address + 1, pk, crypto_sign_PUBLICKEYBYTES);
  return 0;
}

uint8_t get_address_id(uint8_t *address)
{
  return address[0];
}

int valid_address(uint8_t *address)
{
  uint8_t address_id = get_address_id(address);
  switch(address_id)
  {
    case MAINNET_ADDRESS_ID:
    case TESTNET_ADDRESS_ID:
    {
      return 1;
    }
    default:
    {
      return 0;
    }
  }
}
