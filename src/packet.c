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

#include <gossip.h>

#include "chain.h"
#include "net.h"
#include "vulkan.pb-c.h"

#include "packet.h"

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

int packet_to_serialized(uint8_t **buffer, uint32_t *buffer_len, packet_t *packet)
{
  PPacket *msg = packet_to_proto(packet);

  *buffer_len = ppacket__get_packed_size(msg);
  *buffer = malloc(*buffer_len);

  ppacket__pack(msg, *buffer);
  free_proto_packet(msg);

  return 0;
}

packet_t *packet_from_proto(PPacket *proto_packet)
{
  packet_t *packet = malloc(sizeof(packet_t));

  packet->id = proto_packet->id;
  packet->message_size = proto_packet->message_size;

  memcpy(packet->message, proto_packet->message.data, proto_packet->message_size);

  return packet;
}

packet_t *packet_from_serialized(uint8_t *buffer, uint32_t buffer_len)
{
  PPacket *proto_packet = ppacket__unpack(NULL, buffer_len, buffer);
  packet_t *packet = packet_from_proto(proto_packet);
  ppacket__free_unpacked(proto_packet, NULL);

  return packet;
}

int deserialize_packet(void *message, packet_t *packet)
{
  switch (packet->id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        MIncomingBlock *proto_message = mincoming_block__unpack(NULL, packet->message_size, packet->message);

        incoming_block_t *message_object = malloc(sizeof(incoming_block_t));
        message_object->block = block_from_proto(*proto_message->block);

        mincoming_block__free_unpacked(proto_message, NULL);
        break;
      }
    case PKT_TYPE_INCOMING_TRANSACTION:
      {
        MIncomingTransaction *proto_message = mincoming_transaction__unpack(NULL, packet->message_size, packet->message);

        incoming_transaction_t *message_object = malloc(sizeof(incoming_transaction_t));
        message_object->transaction = transaction_from_proto(*proto_message->transaction);

        mincoming_transaction__free_unpacked(proto_message, NULL);
        break;
      }
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
    case PKT_TYPE_GET_BLOCK_REQ:
    case PKT_TYPE_GET_BLOCK_RESP:
    case PKT_TYPE_GET_TRANSACTION_REQ:
    case PKT_TYPE_GET_TRANSACTION_RESP:
      break;
    default:
      fprintf(stderr, "Could not deserialize packet with unknown packet_id: %d\n", packet->id);
      return 1;
  }
  return 0;
}

int serialize_packet(packet_t *packet, uint32_t packet_id, void *message)
{
  uint8_t **buffer = NULL;
  uint32_t *buffer_len = 0;

  switch (packet_id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        MIncomingBlock *msg = malloc(sizeof(MIncomingBlock));
        mincoming_block__init(msg);

        incoming_block_t *message_object = (incoming_block_t*)message;
        message = message_object;

        PBlock *proto_block = block_to_proto(message_object->block);
        msg->block = &proto_block;

        *buffer_len = mincoming_block__get_packed_size(msg);
        *buffer = malloc(*buffer_len);

        mincoming_block__pack(msg, *buffer);

        free(msg);
        free_proto_block(proto_block);
        free(message_object);
      }
      break;
    case PKT_TYPE_INCOMING_TRANSACTION:
      {
        MIncomingTransaction *msg = malloc(sizeof(MIncomingTransaction));
        mincoming_transaction__init(msg);

        incoming_transaction_t *message_object = (incoming_transaction_t*)message;
        message = message_object;

        PTransaction *proto_transaction = transaction_to_proto(message_object->transaction);
        msg->transaction = &proto_transaction;

        *buffer_len = mincoming_transaction__get_packed_size(msg);
        *buffer = malloc(*buffer_len);

        mincoming_transaction__pack(msg, *buffer);

        free(msg);
        free_proto_transaction(proto_transaction);
        free(message_object);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
    case PKT_TYPE_GET_BLOCK_REQ:
    case PKT_TYPE_GET_BLOCK_RESP:
    case PKT_TYPE_GET_TRANSACTION_REQ:
    case PKT_TYPE_GET_TRANSACTION_RESP:
      break;
    default:
      fprintf(stderr, "Could not serialize packet with unknown packet_id: %d\n", packet->id);
      return 1;
  }

  packet = make_packet(packet_id, *buffer_len, *buffer);
  return 0;
}

int handle_packet(pittacus_gossip_t *gossip, uint32_t packet_id, void *message)
{
  switch (packet_id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        incoming_block_t *message_object = (incoming_block_t*)message;
        insert_block_into_blockchain(message_object->block);
        free(message_object);
      }
      break;
    case PKT_TYPE_INCOMING_TRANSACTION:
      {
        incoming_transaction_t *message_object = (incoming_transaction_t*)message;
        insert_tx_into_index(message_object->transaction->id, message_object->transaction);
        free(message_object);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
    case PKT_TYPE_GET_BLOCK_REQ:
    case PKT_TYPE_GET_BLOCK_RESP:
    case PKT_TYPE_GET_TRANSACTION_REQ:
    case PKT_TYPE_GET_TRANSACTION_RESP:
      break;
    default:
      fprintf(stderr, "Could not handle packet with unknown packet_id: %d\n", packet_id);
      return 1;
  }
  return 0;
}

int handle_receive_packet(pittacus_gossip_t *gossip, const uint8_t *data, size_t data_size)
{
  void *message = NULL;
  packet_t *packet = packet_from_serialized((uint8_t*)data, (uint32_t)data_size);
  if (deserialize_packet(message, packet))
  {
    return 1;
  }

  if (handle_packet(gossip, packet->id, message))
  {
    return 1;
  }
  return 0;
}

int handle_send_packet(pittacus_gossip_t *gossip, uint32_t packet_id, void *message)
{
  packet_t *packet = NULL;
  if (serialize_packet(packet, packet_id, message))
  {
    return 1;
  }

  uint8_t **buffer = NULL;
  uint32_t *buffer_len = 0;

  packet_to_serialized(buffer, buffer_len, packet);
  net_send_data(gossip, (const uint8_t*)buffer, (size_t)buffer_len);
  return 0;
}
