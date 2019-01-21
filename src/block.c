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
#include <string.h>

#include <sodium.h>

#include "chainparams.h"
#include "cryptoutil.h"
#include "block.h"
#include "merkle.h"
#include "vulkan.pb-c.h"

/* Allocates a block for usage.
 *
 * Later to be free'd with `free_block`
 */
block_t *make_block(void)
{
  block_t *block = malloc(sizeof(block_t));

  block->version = BLOCK_VERSION;
  block->nonce = 0;

  for (int i = 0; i < HASH_SIZE; i++)
  {
    block->previous_hash[i] = 0x00;
    block->hash[i] = 0x00;
  }

  memcpy(block->merkle_root, &genesis_block.merkle_root, HASH_SIZE);

  block->bits = INITIAL_DIFFICULTY_BITS;
  block->timestamp = 0;
  block->transaction_count = 0;

  return block;
}

int hash_block(block_t *block)
{
  uint8_t header[BLOCK_HEADER_SIZE];

  get_block_header(header, block);
  crypto_hash_sha256(block->hash, header, HASH_SIZE + 1 + 1);

  return 0;
}

// Block is valid if:
// - Timestamp is stamped for a 2 hour drift
// - The first TX is a generational TX
// - TXs don't share any hash IDs
// - TXs don't have any same TXINs referencing the same txout + id
// - TXs TXINs reference UXTOs
// - The block hash is valid
// - The merkle root is valid
//
// Returns 0 if invalid, 1 is valid.
int valid_block(block_t *block)
{
  // Block must have a non-zero number of TXs.
  if (block->transaction_count < 1)
  {
    return 0;
  }

  // First TX must always be a generational TX.
  if (is_generation_tx(block->transactions[0]) != 1)
  {
    return 0;
  }

  // For each TX, compare to the other TXs that:
  // - No other TX shares the same hash id
  // - No other TX shares the same TXIN referencing the same txout + id
  for (int first_tx_index = 0; first_tx_index < block->transaction_count; first_tx_index++)
  {
    transaction_t *first_tx = block->transactions[first_tx_index];

    // check to see if we have more than one generational transaction
    if (first_tx_index != 0 && is_generation_tx(first_tx))
    {
      return 0;
    }

    // check to see if this is a valid transaction
    if (!valid_transaction(first_tx))
    {
      return 0;
    }

    for (int second_tx_index = 0; second_tx_index < block->transaction_count; second_tx_index++)
    {
      transaction_t *second_tx = block->transactions[second_tx_index];
      if (first_tx_index == second_tx_index)
      {
        continue;
      }

      // check to see if any transactions have duplicate transaction hash ids
      if (memcmp(first_tx->id, second_tx->id, HASH_SIZE) == 0)
      {
        return 0;
      }

      // check to see if any transactions reference same txout id + index
      for (int first_txin_index = 0; first_txin_index < block->transactions[first_tx_index]->txin_count; first_txin_index++)
      {
        input_transaction_t *txin_first = first_tx->txins[first_tx_index];
        for (int second_txin_index = 0; second_txin_index < block->transactions[second_tx_index]->txin_count; second_txin_index++)
        {
          input_transaction_t *txin_second = second_tx->txins[second_txin_index];
          if (memcmp(txin_first->transaction, txin_second->transaction, HASH_SIZE) == 0 && txin_first->txout_index == txin_second->txout_index)
          {
            return 0;
          }
        }
      }
    }
  }

  // check the block hash
  if (!valid_block_hash(block))
  {
    return 0;
  }

  // check the merkle root
  if (!valid_merkle_root(block))
  {
    return 0;
  }

  return 1;
}

int valid_merkle_root(block_t *block)
{
  uint8_t *merkle_root = malloc(sizeof(uint8_t) * HASH_SIZE);
  compute_merkle_root(merkle_root, block);

  if (memcmp(merkle_root, block->merkle_root, HASH_SIZE) == 0)
  {
    return 1;
  }
  else
  {
    return 0;
  }
}

int valid_block_hash(block_t *block)
{
  uint32_t target = block->bits;
  uint32_t current_target = 0;

  for (int i = 0; i < HASH_SIZE; i++)
  {
    uint8_t byte = block->hash[i];
    uint32_t n = 0;

    if (byte <= 0x0F)
    {
      n = n + 4;
      byte = byte << 4;
    }

    if (byte <= 0x3F)
    {
      n = n + 2;
      byte = byte << 2;
    }

    if (byte <= 0x7F)
    {
      n = n + 1;
    }

    current_target += n;
  }

  if (current_target > target)
  {
    return 1;
  }
  else
  {
    return 0;
  }
}

int compute_merkle_root(uint8_t *merkle_root, block_t *block)
{
  uint8_t *hashes = malloc(sizeof(uint8_t) * HASH_SIZE * block->transaction_count);
  for (int i = 0; i < block->transaction_count; i++)
  {
    compute_tx_id(&hashes[HASH_SIZE * i], block->transactions[i]);
  }

  merkle_tree_t *tree = construct_merkle_tree_from_leaves(hashes, block->transaction_count);
  memcpy(merkle_root, tree->root->hash, HASH_SIZE);

  free_merkle_tree(tree);
  free(hashes);
  return 0;
}

int compute_self_merkle_root(block_t *block)
{
  compute_merkle_root(block->merkle_root, block);
  return 0;
}

int get_block_header(uint8_t *block_header, block_t *block)
{
  uint32_t position = 0;

  memcpy(block_header + position, &block->version, 1);
  position += 1;
  memcpy(block_header + position, &block->bits, 1);
  position += 1;
  memcpy(block_header + position, &block->nonce, 4);
  position += 4;
  memcpy(block_header + position, &block->timestamp, 4);
  position += 4;
  memcpy(block_header + position, &block->previous_hash, HASH_SIZE);
  position += HASH_SIZE;
  memcpy(block_header + position, &block->merkle_root, HASH_SIZE);
  position += HASH_SIZE;

  return 0;
}

int print_block(block_t *block)
{
  char hash[(crypto_hash_sha256_BYTES * 2) + 1];
  char previous_hash[(crypto_hash_sha256_BYTES * 2) + 1];
  char merkle_root[(crypto_hash_sha256_BYTES * 2) + 1];

  for (int i = 0; i < crypto_hash_sha256_BYTES; i++)
  {
    sprintf(&hash[i*2], "%02x", (unsigned int) block->hash[i]);
  }

  for (int i = 0; i < crypto_hash_sha256_BYTES; i++)
  {
    sprintf(&previous_hash[i*2], "%02x", (unsigned int) block->previous_hash[i]);
  }

  for (int i = 0; i < crypto_hash_sha256_BYTES; i++)
  {
    sprintf(&merkle_root[i*2], "%02x", (unsigned int) block->merkle_root[i]);
  }

  printf("Block:\n");
  printf("Version: %d\n", block->version);
  printf("Bits: %d\n", block->bits);
  printf("Nonce: %d\n", block->nonce);
  printf("Timestamp (epoch): %d\n", block->timestamp);
  printf("Previous Hash: %s\n", previous_hash);
  printf("Merkle Root: %s\n", merkle_root);
  printf("Hash: %s\n", hash);
  return 0;
}

int compare_with_genesis_block(block_t *block)
{
  hash_block(block);
  hash_block(&genesis_block);

  for (int i = 0; i < HASH_SIZE; i++)
  {
    if (block->hash[i] != genesis_block.hash[i])
    {
      return 1;
    }
  }

  return 0;
}

/*
 * Converts an allocated block to a newly allocated protobuf
 * block struct.
 *
 * Later to be free'd with `free_proto_block`
 */
PBlock *block_to_proto(block_t *block)
{
  PBlock *msg = malloc(sizeof(PBlock));
  pblock__init(msg);

  msg->version = block->version;
  msg->bits = block->bits;

  msg->previous_hash.len = HASH_SIZE;
  msg->previous_hash.data = malloc(sizeof(char) * HASH_SIZE);
  memcpy(msg->previous_hash.data, block->previous_hash, HASH_SIZE);

  msg->hash.len = HASH_SIZE;
  msg->hash.data = malloc(sizeof(char) * HASH_SIZE);
  memcpy(msg->hash.data, block->hash, HASH_SIZE);

  msg->timestamp = block->timestamp;
  msg->nonce = block->nonce;

  msg->merkle_root.len = HASH_SIZE;
  msg->merkle_root.data = malloc(sizeof(char) * HASH_SIZE);
  memcpy(msg->merkle_root.data, block->merkle_root, HASH_SIZE);

  msg->n_transactions = block->transaction_count;
  msg->transactions = malloc(sizeof(PTransaction *) * msg->n_transactions);

  for (int i = 0; i < msg->n_transactions; i++)
  {
    msg->transactions[i] = transaction_to_proto(block->transactions[i]);
  }

  return msg;
}

int block_to_serialized(uint8_t **buffer, uint32_t *buffer_len, block_t *block)
{
  PBlock *msg = block_to_proto(block);

  *buffer_len = pblock__get_packed_size(msg);
  *buffer = malloc(*buffer_len);

  pblock__pack(msg, *buffer);
  free_proto_block(msg);

  return 0;
}

block_t *block_from_proto(PBlock *proto_block)
{
  block_t *block = malloc(sizeof(block_t));

  block->version = proto_block->version;
  block->bits = proto_block->bits;

  memcpy(block->previous_hash, proto_block->previous_hash.data, HASH_SIZE);
  memcpy(block->hash, proto_block->hash.data, HASH_SIZE);
  memcpy(block->merkle_root, proto_block->merkle_root.data, HASH_SIZE);

  block->timestamp = proto_block->timestamp;
  block->nonce = proto_block->nonce;

  // @TODO(vy): unpack transactions into struct
  block->transaction_count = proto_block->n_transactions;
  block->transactions = malloc(sizeof(transaction_t *) * block->transaction_count);

  for (int i = 0; i < block->transaction_count; i++)
  {
    block->transactions[i] = transaction_from_proto(proto_block->transactions[i]);
  }

  return block;
}

block_t *block_from_serialized(uint8_t *buffer, uint32_t buffer_len)
{
  PBlock *proto_block = pblock__unpack(NULL, buffer_len, buffer);
  block_t *block = block_from_proto(proto_block);
  pblock__free_unpacked(proto_block, NULL);

  return block;
}

int free_proto_block(PBlock *proto_block)
{
  free(proto_block->previous_hash.data);
  free(proto_block->hash.data);
  free(proto_block->merkle_root.data);

  for (int i = 0; i < proto_block->n_transactions; i++)
  {
    free_proto_transaction(proto_block->transactions[i]);
  }

  free(proto_block->transactions);
  free(proto_block);
  return 0;
}

/*
 * Frees an allocated block, and its corresponding TXs.
 */
int free_block(block_t *block)
{
  for (int i = 0; i < block->transaction_count; i++)
  {
    free_transaction(block->transactions[i]);
  }

  if (block->transaction_count > 0)
  {
    free(block->transactions);
  }

  free(block);
  return 0;
}
