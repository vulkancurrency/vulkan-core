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
#include <inttypes.h>

#include <sodium.h>

#ifdef USE_LEVELDB
#include <leveldb/c.h>
#else
#include <rocksdb/c.h>
#endif

#include "common/buffer.h"
#include "common/logger.h"
#include "common/util.h"

#include "core/blockchain.h"
#include "core/mempool.h"
#include "core/parameters.h"

#include "crypto/sha256d.h"

#include "wallet/wallet.h"

wallet_t* make_wallet(void)
{
  wallet_t *wallet = malloc(sizeof(wallet_t));
  wallet->balance = 0;
  return wallet;
}

void free_wallet(wallet_t *wallet)
{
  assert(wallet != NULL);
  free(wallet);
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

int deserialize_wallet(buffer_iterator_t *buffer_iterator, wallet_t **wallet_out)
{
  assert(buffer_iterator != NULL);
  wallet_t *wallet = make_wallet();

  uint8_t *secret_key = NULL;
  if (buffer_read_bytes(buffer_iterator, &secret_key))
  {
    return 1;
  }

  memcpy(&wallet->secret_key, secret_key, crypto_sign_SECRETKEYBYTES);
  free(secret_key);

  uint8_t *public_key = NULL;
  if (buffer_read_bytes(buffer_iterator, &public_key))
  {
    return 1;
  }

  memcpy(&wallet->public_key, public_key, crypto_sign_PUBLICKEYBYTES);
  free(public_key);

  uint8_t *address = NULL;
  if (buffer_read_bytes(buffer_iterator, &address))
  {
    return 1;
  }

  memcpy(&wallet->address, address, ADDRESS_SIZE);
  free(address);

  wallet->balance = 0;
  if (buffer_read_uint64(buffer_iterator, &wallet->balance))
  {
    return 1;
  }

  *wallet_out = wallet;
  return 0;
}

/*
 * open_wallet()
 * Opens a LevelDB instance for the wallet
 */
#ifdef USE_LEVELDB
leveldb_t* open_wallet(const char *wallet_dir, char *err)
{
  leveldb_t *db;
  leveldb_options_t *options = leveldb_options_create();
  leveldb_options_set_create_if_missing(options, 1);
  return leveldb_open(options, wallet_dir, &err);
}
#else
rocksdb_t* open_wallet(const char *wallet_dir, char *err)
{
  rocksdb_t *db;
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(options, 1);
  return rocksdb_open(options, wallet_dir, &err);
}
#endif

int new_wallet(const char *wallet_dir, wallet_t **wallet_out)
{
  char *err = NULL;
#ifdef USE_LEVELDB
  leveldb_t *db = open_wallet(wallet_dir, err);
#else
  rocksdb_t *db = open_wallet(wallet_dir, err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Could not open wallet: %s!", wallet_dir);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_close(db);
  #else
    rocksdb_free(err);
    rocksdb_close(db);
  #endif

    return 1;
  }

  size_t read_len;
#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  uint8_t *initialized = (uint8_t*)leveldb_get(db, roptions, "0", 1, &read_len, &err);
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *initialized = (uint8_t*)rocksdb_get(db, roptions, "0", 1, &read_len, &err);
#endif

  if (initialized != NULL)
  {
  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_readoptions_destroy(roptions);
    leveldb_close(db);
  #else
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    rocksdb_close(db);
  #endif

    return 1;
  }

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  unsigned char seed[crypto_sign_SEEDBYTES];
  unsigned char address[ADDRESS_SIZE];

  crypto_sign_keypair(pk, sk);
  crypto_sign_ed25519_sk_to_seed(seed, sk);
  public_key_to_address(address, pk);

  wallet_t *wallet = make_wallet();
  memcpy(&wallet->secret_key, &sk, crypto_sign_SECRETKEYBYTES);
  memcpy(&wallet->public_key, &pk, crypto_sign_PUBLICKEYBYTES);
  memcpy(&wallet->address, &address, ADDRESS_SIZE);
  wallet->balance = 0;

  buffer_t *buffer = buffer_init();
  serialize_wallet(buffer, wallet);

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

#ifdef USE_LEVELDB
  leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
  leveldb_put(db, woptions, "0", 1, (char*)data, data_len, &err);
#else
  rocksdb_writeoptions_t *woptions = rocksdb_writeoptions_create();
  rocksdb_put(db, woptions, "0", 1, (char*)data, data_len, &err);
#endif
  buffer_free(buffer);

  if (err != NULL)
  {
    LOG_ERROR("Could not write to wallet: %s database!", wallet_dir);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_readoptions_destroy(roptions);
    leveldb_writeoptions_destroy(woptions);
    leveldb_close(db);
  #else
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    rocksdb_writeoptions_destroy(woptions);
    rocksdb_close(db);
  #endif

    return 1;
  }

  LOG_INFO("Successfully created new wallet: %s", wallet_dir);

#ifdef USE_LEVELDB
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
  leveldb_writeoptions_destroy(woptions);
  leveldb_close(db);
#else
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  rocksdb_writeoptions_destroy(woptions);
  rocksdb_close(db);
#endif

  *wallet_out = wallet;
  return 0;
}

int get_wallet(const char *wallet_dir, wallet_t **wallet_out)
{
  char *err = NULL;

#ifdef USE_LEVELDB
  leveldb_t *db = open_wallet(wallet_dir, err);
#else
  rocksdb_t *db = open_wallet(wallet_dir, err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Could not open wallet database: %s!", wallet_dir);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_close(db);
  #else
    rocksdb_free(err);
    rocksdb_close(db);
  #endif

    return 1;
  }

  size_t read_len;
#ifdef USE_LEVELDB
  leveldb_readoptions_t *roptions = leveldb_readoptions_create();
  uint8_t *wallet_data = (uint8_t*)leveldb_get(db, roptions, "0", 1, &read_len, &err);
#else
  rocksdb_readoptions_t *roptions = rocksdb_readoptions_create();
  uint8_t *wallet_data = (uint8_t*)rocksdb_get(db, roptions, "0", 1, &read_len, &err);
#endif

  if (err != NULL || wallet_data == NULL)
  {
    LOG_ERROR("Could not open wallet database: %s!", wallet_dir);

  #ifdef USE_LEVELDB
    leveldb_free(err);
    leveldb_readoptions_destroy(roptions);
    leveldb_close(db);
  #else
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    rocksdb_close(db);
  #endif
    return 1;
  }

  buffer_t *buffer = buffer_init_data(0, wallet_data, read_len);
  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);

  wallet_t *wallet = NULL;
  if (deserialize_wallet(buffer_iterator, &wallet))
  {
    buffer_iterator_free(buffer_iterator);
    buffer_free(buffer);

  #ifdef USE_LEVELDB
    leveldb_free(wallet_data);
    leveldb_free(err);
    leveldb_readoptions_destroy(roptions);
    leveldb_close(db);
  #else
    rocksdb_free(wallet_data);
    rocksdb_free(err);
    rocksdb_readoptions_destroy(roptions);
    rocksdb_close(db);
  #endif
    return 1;
  }

  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);

  LOG_INFO("Successfully opened wallet: %s", wallet_dir);

#ifdef USE_LEVELDB
  leveldb_free(wallet_data);
  leveldb_free(err);
  leveldb_readoptions_destroy(roptions);
  leveldb_close(db);
#else
  rocksdb_free(wallet_data);
  rocksdb_free(err);
  rocksdb_readoptions_destroy(roptions);
  rocksdb_close(db);
#endif

  *wallet_out = wallet;
  return 0;
}

int init_wallet(const char *wallet_dir, wallet_t **wallet_out)
{
  wallet_t *wallet = NULL;
  if (new_wallet(wallet_dir, &wallet))
  {
    return 1;
  }

  if (wallet == NULL)
  {
    if (get_wallet(wallet_dir, &wallet))
    {
      return 1;
    }
  }

  *wallet_out = wallet;
  return 0;
}

int remove_wallet(const char *wallet_dir)
{
  char *err = NULL;
#ifdef USE_LEVELDB
  leveldb_options_t *options = leveldb_options_create();
  leveldb_destroy_db(options, wallet_dir, &err);
#else
  rocksdb_options_t *options = rocksdb_options_create();
  rocksdb_destroy_db(options, wallet_dir, &err);
#endif

  if (err != NULL)
  {
    LOG_ERROR("Failed to remove wallet database: %s!", err);
  #ifdef USE_LEVELDB
    leveldb_options_destroy(options);
  #else
    rocksdb_options_destroy(options);
  #endif
    return 1;
  }

#ifdef USE_LEVELDB
  leveldb_options_destroy(options);
#else
  rocksdb_options_destroy(options);
#endif
  return 0;
}

void print_wallet(wallet_t *wallet)
{
  assert(wallet != NULL);
  uint64_t balance = get_balance_for_address(wallet->address) / COIN;

  char *public_address_str = address_to_str(wallet->address);
  printf("Public Address: %s\n", public_address_str);
  free(public_address_str);

  printf("Balance: %" PRIu64 "\n", balance);
}

void print_public_key(wallet_t *wallet)
{
  assert(wallet != NULL);
  char *public_key_str = bytes_to_str(wallet->public_key, crypto_sign_PUBLICKEYBYTES);
  printf("Public Key: %s\n", public_key_str);
  free(public_key_str);
}

void print_secret_key(wallet_t *wallet)
{
  assert(wallet != NULL);
  char *secret_key_str = bytes_to_str(wallet->secret_key, crypto_sign_SECRETKEYBYTES);
  printf("Secret Key: %s\n", secret_key_str);
  free(secret_key_str);
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
