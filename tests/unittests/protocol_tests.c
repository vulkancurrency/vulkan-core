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
#include <sodium.h>

#include "common/greatest.h"
#include "common/buffer.h"
#include "common/util.h"

#include "core/block.h"
#include "core/transaction.h"
#include "core/protocol.h"

SUITE(protocol_suite);

TEST can_serialize_deserialize_packet(void)
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
  tx->txins = malloc(sizeof(input_transaction_t *) * 1);
  tx->txins[0] = txin;

  block_t *block = make_block();
  block->nonce = 50;
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t *) * 1);
  block->transactions[0] = tx;

  // serialize packet
  buffer_t *buffer = buffer_init();
  serialize_block(buffer, block);

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  packet_t *packet = make_packet();
  packet->size = data_len;
  packet->data = malloc(data_len);
  memcpy(packet->data, data, data_len);
  ASSERT_MEM_EQ(data, packet->data, data_len);

  buffer_t *buffer2 = buffer_init();
  serialize_packet(buffer2, packet);
  buffer_free(buffer);
  free_packet(packet);

  // deserialize packet
  buffer_set_offset(buffer2, 0);
  packet_t *packet2 = make_packet();
  deserialize_packet(packet2, buffer2);
  buffer_free(buffer2);

  buffer_t *buffer3 = buffer_init_data(0, packet2->data, packet2->size);
  block_t *deserialized_block = deserialize_block(buffer3);
  ASSERT(deserialized_block != NULL);
  buffer_free(buffer3);
  free_packet(packet2);

  // check the block to see if it was properly constructed
  ASSERT_EQ(deserialized_block->version, block->version);
  ASSERT_EQ(deserialized_block->bits, block->bits);

  ASSERT_MEM_EQ(deserialized_block->previous_hash, block->previous_hash, HASH_SIZE);
  ASSERT_MEM_EQ(deserialized_block->hash, block->hash, HASH_SIZE);

  ASSERT_EQ(deserialized_block->timestamp, block->timestamp);
  ASSERT_EQ(deserialized_block->nonce, block->nonce);
  ASSERT_EQ(deserialized_block->already_generated_coins, block->already_generated_coins);

  ASSERT_MEM_EQ(deserialized_block->merkle_root, block->merkle_root, HASH_SIZE);
  ASSERT_EQ(deserialized_block->transaction_count, block->transaction_count);

  free_block(block);
  free_block(deserialized_block);
  PASS();
}

GREATEST_SUITE(protocol_suite)
{
  RUN_TEST(can_serialize_deserialize_packet);
}
