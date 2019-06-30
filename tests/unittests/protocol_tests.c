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

#include "common/buffer_iterator.h"
#include "common/buffer.h"
#include "common/greatest.h"
#include "common/mongoose.h"
#include "common/util.h"

#include "core/block.h"
#include "core/net.h"
#include "core/p2p.h"
#include "core/protocol.h"
#include "core/transaction.h"

#include "crypto/cryptoutil.h"

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
  tx->txouts = malloc(sizeof(output_transaction_t) * 1);
  tx->txouts[0] = txout;

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  crypto_sign_keypair(pk, sk);
  sign_txin(txin, tx, pk, sk);

  tx->txin_count = 1;
  tx->txins = malloc(sizeof(input_transaction_t) * 1);
  tx->txins[0] = txin;

  block_t *block = make_block();
  block->nonce = 50;
  block->transaction_count = 1;
  block->transactions = malloc(sizeof(transaction_t) * 1);
  block->transactions[0] = tx;

  // serialize packet
  buffer_t *buffer = buffer_init();
  ASSERT(serialize_block(buffer, block) == 0);

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  packet_t *packet = make_packet();
  packet->size = data_len;
  packet->data = malloc(data_len);
  memcpy(packet->data, data, data_len);
  ASSERT_MEM_EQ(data, packet->data, data_len);
  buffer_free(buffer);

  buffer_t *buffer2 = buffer_init();
  ASSERT(serialize_packet(buffer2, packet) == 0);
  free_packet(packet);

  // deserialize packet
  buffer_iterator_t *buffer_iterator1 = buffer_iterator_init(buffer2);
  packet_t *packet2 = make_packet();

  ASSERT(deserialize_packet(packet2, buffer_iterator1) == 0);
  ASSERT(buffer_get_remaining_size(buffer_iterator1) == 0);

  buffer_iterator_free(buffer_iterator1);
  buffer_free(buffer2);

  buffer_t *buffer3 = buffer_init_data(0, packet2->data, packet2->size);
  buffer_iterator_t *buffer_iterator2 = buffer_iterator_init(buffer3);

  block_t *deserialized_block = NULL;
  ASSERT(deserialize_block(buffer_iterator2, &deserialized_block) == 0);

  buffer_iterator_free(buffer_iterator2);
  buffer_free(buffer3);
  free_packet(packet2);

  ASSERT_EQ(deserialized_block->version, block->version);

  ASSERT_MEM_EQ(deserialized_block->previous_hash, block->previous_hash, HASH_SIZE);
  ASSERT_MEM_EQ(deserialized_block->hash, block->hash, HASH_SIZE);

  ASSERT_EQ(deserialized_block->timestamp, block->timestamp);
  ASSERT_EQ(deserialized_block->nonce, block->nonce);
  ASSERT_EQ(deserialized_block->bits, block->bits);
  ASSERT_EQ(deserialized_block->cumulative_emission, block->cumulative_emission);

  ASSERT_MEM_EQ(deserialized_block->merkle_root, block->merkle_root, HASH_SIZE);
  ASSERT_EQ(deserialized_block->transaction_count, block->transaction_count);

  free_block(block);
  free_block(deserialized_block);
  PASS();
}

TEST can_add_and_remove_peer_from_peerlist(void)
{
  uint64_t peer_id = 1;

  struct mg_connection *nc = malloc(sizeof(struct mg_connection));
  net_connection_t *net_connection = init_net_connection(nc);
  ASSERT(net_connection != NULL);

  peer_t *peer = init_peer(peer_id, net_connection);
  ASSERT(peer != NULL);
  ASSERT(add_peer(peer) == 0);
  ASSERT(has_peer(peer_id) == 1);

  peer_t *peer2 = get_peer(peer_id);
  ASSERT(peer2 != NULL);
  ASSERT(peer == peer2);
  ASSERT(remove_peer(peer) == 0);

  free_net_connection(net_connection);
  free(nc);

  PASS();
}

GREATEST_SUITE(protocol_suite)
{
  RUN_TEST(can_serialize_deserialize_packet);
  RUN_TEST(can_add_and_remove_peer_from_peerlist);
}
