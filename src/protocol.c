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

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <gossip.h>

#include "cryptoutil.h"
#include "chain.h"
#include "net.h"
#include "mempool.h"
#include "vulkan.pb-c.h"

#include "protocol.h"

packet_t *make_packet(uint32_t packet_id, uint32_t message_size, uint8_t *message)
{
  packet_t *packet = malloc(sizeof(packet_t));

  packet->id = packet_id;
  packet->message_size = message_size;
  packet->message = message;

  return packet;
}

int free_packet(packet_t *packet)
{
  free(packet);
  return 0;
}

PPacket *packet_to_proto(packet_t *packet)
{
  PPacket *msg = malloc(sizeof(PPacket));
  ppacket__init(msg);

  msg->id = packet->id;
  msg->message_size = packet->message_size;

  msg->message.len = packet->message_size;
  msg->message.data = malloc(sizeof(char) * packet->message_size);
  memcpy(msg->message.data, packet->message, packet->message_size);

  return msg;
}

int free_proto_packet(PPacket *proto_packet)
{
  free(proto_packet->message.data);
  free(proto_packet);
  return 0;
}

int packet_to_serialized(uint8_t **buffer, size_t *buffer_len, packet_t *packet)
{
  PPacket *msg = packet_to_proto(packet);

  size_t buff_len = ppacket__get_packed_size(msg);
  uint8_t *buff = malloc(buff_len);

  ppacket__pack(msg, buff);
  free_proto_packet(msg);

  *buffer_len = buff_len;
  *buffer = buff;

  return 0;
}

packet_t *packet_from_proto(PPacket *proto_packet)
{
  packet_t *packet = malloc(sizeof(packet_t));

  packet->id = proto_packet->id;
  packet->message_size = proto_packet->message_size;

  packet->message = malloc(proto_packet->message_size);
  memcpy(packet->message, proto_packet->message.data, proto_packet->message_size);

  return packet;
}

packet_t *packet_from_serialized(const uint8_t *buffer, size_t buffer_len)
{
  PPacket *proto_packet = ppacket__unpack(NULL, buffer_len, buffer);
  packet_t *packet = packet_from_proto(proto_packet);
  ppacket__free_unpacked(proto_packet, NULL);

  return packet;
}

void* deserialize_packet(packet_t *packet)
{
  switch (packet->id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        MIncomingBlock *proto_message = mincoming_block__unpack(NULL,
          packet->message_size, packet->message);

        incoming_block_t *message = malloc(sizeof(incoming_block_t));
        message->block = block_from_proto(proto_message->block);

        mincoming_block__free_unpacked(proto_message, NULL);
        return message;
      }
    case PKT_TYPE_INCOMING_TRANSACTION:
      {
        MIncomingTransaction *proto_message = mincoming_transaction__unpack(NULL,
          packet->message_size, packet->message);

        incoming_transaction_t *message = malloc(sizeof(incoming_transaction_t));
        message->transaction = transaction_from_proto(proto_message->transaction);

        mincoming_transaction__free_unpacked(proto_message, NULL);
        return message;
      }
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {
        MGetBlockHeightRequest *proto_message = mget_block_height_request__unpack(NULL,
          packet->message_size, packet->message);

        get_block_height_request_t *message = malloc(sizeof(get_block_height_request_t));
        mget_block_height_request__free_unpacked(proto_message, NULL);
        return message;
      }
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      {
        MGetBlockHeightResponse *proto_message = mget_block_height_response__unpack(NULL,
          packet->message_size, packet->message);

        get_block_height_response_t *message = malloc(sizeof(get_block_height_response_t));
        message->height = proto_message->height;

        message->hash = malloc(HASH_SIZE);
        memcpy(message->hash, proto_message->hash.data, HASH_SIZE);

        mget_block_height_response__free_unpacked(proto_message, NULL);
        return message;
      }
    case PKT_TYPE_GET_BLOCK_REQ:
      {
        MGetBlockRequest *proto_message = mget_block_request__unpack(NULL,
          packet->message_size, packet->message);

        get_block_request_t *message = malloc(sizeof(get_block_request_t));
        message->height = proto_message->height;

        message->hash = malloc(HASH_SIZE);
        memcpy(message->hash, proto_message->hash.data, HASH_SIZE);

        mget_block_request__free_unpacked(proto_message, NULL);
        return message;
      }
    case PKT_TYPE_GET_BLOCK_RESP:
      {
        MGetBlockResponse *proto_message = mget_block_response__unpack(NULL,
          packet->message_size, packet->message);

        get_block_response_t *message = malloc(sizeof(get_block_response_t));
        message->height = proto_message->height;
        message->block = block_from_proto(proto_message->block);

        mget_block_response__free_unpacked(proto_message, NULL);
        return message;
      }
    case PKT_TYPE_GET_TRANSACTION_REQ:
      {
        MGetTransactionRequest *proto_message = mget_transaction_request__unpack(NULL,
          packet->message_size, packet->message);

        get_transaction_request_t *message = malloc(sizeof(get_transaction_request_t));

        message->id = malloc(HASH_SIZE);
        memcpy(message->id, proto_message->id.data, HASH_SIZE);

        message->input_hash = malloc(HASH_SIZE);
        memcpy(message->input_hash, proto_message->input_hash.data, HASH_SIZE);

        mget_transaction_request__free_unpacked(proto_message, NULL);
        return message;
      }
    case PKT_TYPE_GET_TRANSACTION_RESP:
      {
        MGetTransactionResponse *proto_message = mget_transaction_response__unpack(NULL,
          packet->message_size, packet->message);

        get_transaction_response_t *message = malloc(sizeof(get_transaction_response_t));
        message->transaction = transaction_from_proto(proto_message->transaction);

        mget_transaction_response__free_unpacked(proto_message, NULL);
        return message;
      }
    default:
      fprintf(stderr, "Could not deserialize packet with unknown packet id: %d\n", packet->id);
      return NULL;
  }
  return NULL;
}

packet_t* serialize_packet(uint32_t packet_id, va_list args)
{
  uint8_t *buffer = NULL;
  uint32_t buffer_len = 0;

  switch (packet_id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        block_t *block = va_arg(args, block_t*);

        MIncomingBlock *msg = malloc(sizeof(MIncomingBlock));
        mincoming_block__init(msg);

        PBlock *proto_block = block_to_proto(block);
        msg->block = proto_block;

        buffer_len = mincoming_block__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mincoming_block__pack(msg, buffer);

        free(msg);
        free_proto_block(proto_block);
      }
      break;
    case PKT_TYPE_INCOMING_TRANSACTION:
      {
        transaction_t *transaction = va_arg(args, transaction_t*);

        MIncomingTransaction *msg = malloc(sizeof(MIncomingTransaction));
        mincoming_transaction__init(msg);

        PTransaction *proto_transaction = transaction_to_proto(transaction);
        msg->transaction = proto_transaction;

        buffer_len = mincoming_transaction__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mincoming_transaction__pack(msg, buffer);

        free(msg);
        free_proto_transaction(proto_transaction);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {
        MGetBlockHeightRequest *msg = malloc(sizeof(MGetBlockHeightRequest));
        mget_block_height_request__init(msg);

        buffer_len = mget_block_height_request__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_block_height_request__pack(msg, buffer);

        free(msg);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      {
        uint64_t height = va_arg(args, uint64_t);
        uint8_t *hash = va_arg(args, uint8_t*);

        MGetBlockHeightResponse *msg = malloc(sizeof(MGetBlockHeightResponse));
        mget_block_height_response__init(msg);

        msg->height = height;

        msg->hash.len = HASH_SIZE;
        msg->hash.data = malloc(sizeof(char) * HASH_SIZE);
        memcpy(msg->hash.data, hash, HASH_SIZE);

        buffer_len = mget_block_height_response__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_block_height_response__pack(msg, buffer);

        free(msg);
      }
      break;
    case PKT_TYPE_GET_BLOCK_REQ:
      {
        uint64_t height = va_arg(args, uint64_t);
        uint8_t *hash = va_arg(args, uint8_t*);

        MGetBlockRequest *msg = malloc(sizeof(MGetBlockRequest));
        mget_block_request__init(msg);

        msg->height = height;

        msg->hash.len = HASH_SIZE;
        msg->hash.data = malloc(sizeof(char) * HASH_SIZE);
        memcpy(msg->hash.data, hash, HASH_SIZE);

        buffer_len = mget_block_request__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_block_request__pack(msg, buffer);

        free(msg);
      }
      break;
    case PKT_TYPE_GET_BLOCK_RESP:
      {
        uint64_t height = va_arg(args, uint64_t);
        block_t *block = va_arg(args, block_t*);

        MGetBlockResponse *msg = malloc(sizeof(MGetBlockResponse));
        mget_block_response__init(msg);

        msg->height = height;
        msg->block = block_to_proto(block);

        buffer_len = mget_block_response__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_block_response__pack(msg, buffer);

        free(msg);
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_REQ:
      {
        uint8_t *id = va_arg(args, uint8_t*);
        uint8_t *input_hash = va_arg(args, uint8_t*);

        MGetTransactionRequest *msg = malloc(sizeof(MGetTransactionRequest));
        mget_transaction_request__init(msg);

        msg->id.len = HASH_SIZE;
        msg->id.data = malloc(sizeof(char) * HASH_SIZE);
        memcpy(msg->id.data, id, HASH_SIZE);

        msg->input_hash.len = HASH_SIZE;
        msg->input_hash.data = malloc(sizeof(char) * HASH_SIZE);
        memcpy(msg->input_hash.data, input_hash, HASH_SIZE);

        buffer_len = mget_transaction_request__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_transaction_request__pack(msg, buffer);

        free(msg);
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_RESP:
      {
        transaction_t *transaction = va_arg(args, transaction_t*);

        MGetTransactionResponse *msg = malloc(sizeof(MGetTransactionResponse));
        mget_transaction_response__init(msg);

        msg->transaction = transaction_to_proto(transaction);;

        buffer_len = mget_transaction_response__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_transaction_response__pack(msg, buffer);

        free(msg);
      }
      break;
    default:
      fprintf(stderr, "Could not serialize packet with unknown packet id: %d\n", packet_id);
      return NULL;
  }
  return make_packet(packet_id, buffer_len, buffer);
}

int handle_packet(pittacus_gossip_t *gossip, uint32_t packet_id, void *message_object)
{
  switch (packet_id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        incoming_block_t *message = (incoming_block_t*)message_object;
        insert_block_into_blockchain(message->block);
        free(message);
      }
      break;
    case PKT_TYPE_INCOMING_TRANSACTION:
      {
        incoming_transaction_t *message = (incoming_transaction_t*)message_object;
        push_tx_to_mempool(message->transaction);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {
        get_block_height_request_t *message = (get_block_height_request_t*)message_object;
        handle_broadcast_packet(PKT_TYPE_GET_BLOCK_HEIGHT_RESP, get_block_height(), get_current_block_hash());
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      {
        get_block_height_response_t *message = (get_block_height_response_t*)message_object;
        if (message->height > get_block_height())
        {
          handle_broadcast_packet(PKT_TYPE_GET_BLOCK_REQ, message->height, message->hash);
        }
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_REQ:
      {
        get_block_request_t *message = (get_block_request_t*)message_object;
        block_t *block = NULL;
        if (message->height < 0)
        {
          block = get_block_from_hash(message->hash);
        }
        else
        {
          block = get_block_from_height(message->height);
        }
        if (block != NULL)
        {
          handle_broadcast_packet(PKT_TYPE_GET_BLOCK_RESP, message->height, block);
        }
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_RESP:
      {
        get_block_response_t *message = (get_block_response_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_REQ:
      {
        get_transaction_request_t *message = (get_transaction_request_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_RESP:
      {
        get_transaction_response_t *message = (get_transaction_response_t*)message_object;
        free(message);
      }
      break;
    default:
      fprintf(stderr, "Could not handle packet with unknown packet id: %d\n", packet_id);
      return 1;
  }
  return 0;
}

int handle_receive_packet(pittacus_gossip_t *gossip, const uint8_t *data, size_t data_size)
{
  packet_t *packet = packet_from_serialized(data, data_size);
  void *message = deserialize_packet(packet);
  if (!message)
  {
    return 1;
  }

  if (handle_packet(gossip, packet->id, message))
  {
    return 1;
  }

  free(packet);
  return 0;
}

int handle_send_packet(pittacus_gossip_t *gossip, uint32_t packet_id, va_list args)
{
  packet_t *packet = serialize_packet(packet_id, args);
  if (!packet)
  {
    return 1;
  }

  uint8_t *buffer = NULL;
  size_t buffer_len = 0;

  packet_to_serialized(&buffer, &buffer_len, packet);
  net_send_data(gossip, (const uint8_t*)buffer, buffer_len);
  return 0;
}

int handle_broadcast_packet(uint32_t packet_id, ...)
{
  va_list args;
  va_start(args, packet_id);
  if (handle_send_packet(net_get_gossip(), packet_id, args))
  {
    return 1;
  }

  va_end(args);
  return 0;
}
