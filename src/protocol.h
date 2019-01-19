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
#include <stdarg.h>

#include <gossip.h>

#include "block.h"
#include "transaction.h"

#ifdef __cplusplus
extern "C"
{
#endif

enum
{
  PKT_TYPE_INCOMING_BLOCK = 0,
  PKT_TYPE_INCOMING_TRANSACTION,

  PKT_TYPE_GET_BLOCK_HEIGHT_REQ,
  PKT_TYPE_GET_BLOCK_HEIGHT_RESP,

  PKT_TYPE_GET_BLOCK_REQ,
  PKT_TYPE_GET_BLOCK_RESP,

  PKT_TYPE_GET_TRANSACTION_REQ,
  PKT_TYPE_GET_TRANSACTION_RESP
};

typedef struct Packet
{
  uint32_t id;
  uint32_t message_size;
  uint8_t *message;
} packet_t;

typedef struct MIncomingBlock
{
  block_t *block;
} incoming_block_t;

typedef struct MIncomingTransaction
{
  transaction_t *transaction;
} incoming_transaction_t;

typedef struct MGetBlockHeightRequest
{

} get_block_height_request_t;

typedef struct MGetBlockHeightResponse
{
  uint64_t height;
} get_block_height_response_t;

typedef struct MGetBlockRequest
{
  int64_t height;
  uint8_t *hash;
} get_block_request_t;

typedef struct MGetBlockResponse
{
  uint64_t height;
  block_t *block;
} get_block_response_t;

typedef struct MGetTransactionRequest
{
  uint8_t *id;
  uint8_t *input_hash;
} get_transaction_request_t;

typedef struct MGetTransactionResponse
{
  transaction_t *transaction;
} get_transaction_response_t;

packet_t *make_packet(uint32_t packet_id, uint32_t message_size, uint8_t *message);
int free_packet(packet_t *packet);

PPacket *packet_to_proto(packet_t *packet);
int free_proto_packet(PPacket *proto_packet);
int packet_to_serialized(uint8_t **buffer, size_t *buffer_len, packet_t *packet);
packet_t *packet_from_proto(PPacket *proto_packet);
packet_t *packet_from_serialized(const uint8_t *buffer, size_t buffer_len);

packet_t* serialize_packet(uint32_t packet_id, va_list args);
void* deserialize_packet(packet_t *packet);

int handle_packet(pittacus_gossip_t *gossip, uint32_t packet_id, void *message_object);
int handle_receive_packet(pittacus_gossip_t *gossip, const uint8_t *data, size_t data_size);

int handle_send_packet(pittacus_gossip_t *gossip, uint32_t packet_id, ...);
int handle_broadcast_packet(uint32_t packet_id, ...);

#ifdef __cplusplus
}
#endif
