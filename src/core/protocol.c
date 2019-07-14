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
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include "common/buffer.h"
#include "common/logger.h"
#include "common/mongoose.h"
#include "common/util.h"

#include "blockchain.h"
#include "checkpoints.h"
#include "mempool.h"
#include "net.h"
#include "p2p.h"
#include "parameters.h"
#include "protocol.h"
#include "version.h"

#include "crypto/cryptoutil.h"

#include "miner/miner.h"

static sync_entry_t g_protocol_sync_entry;
static int g_protocol_force_version_check = 0;

void set_force_version_check(int force_version_check)
{
  g_protocol_force_version_check = force_version_check;
}

int get_force_version_check(void)
{
  return g_protocol_force_version_check;
}

packet_t* make_packet(void)
{
  packet_t *packet = malloc(sizeof(packet_t));
  assert(packet != NULL);
  packet->id = PKT_TYPE_UNKNOWN;
  packet->size = 0;
  packet->data = NULL;
  return packet;
}

int serialize_packet(buffer_t *buffer, packet_t *packet)
{
  assert(buffer != NULL);
  assert(packet != NULL);

  buffer_write_uint32(buffer, packet->id);
  buffer_write_uint32(buffer, packet->size);
  if (packet->size > 0)
  {
    buffer_write_bytes(buffer, packet->data, packet->size);
  }

  return 0;
}

int deserialize_packet(packet_t *packet, buffer_iterator_t *buffer_iterator)
{
  assert(packet != NULL);
  assert(buffer_iterator != NULL);

  if (buffer_read_uint32(buffer_iterator, &packet->id))
  {
    return 1;
  }

  if (buffer_read_uint32(buffer_iterator, &packet->size))
  {
    return 1;
  }

  if (packet->size > 0)
  {
    uint8_t *data = NULL;
    if (buffer_read_bytes(buffer_iterator, &data))
    {
      return 1;
    }

    packet->data = malloc(packet->size);
    assert(packet->data != NULL);
    memcpy(packet->data, data, packet->size);
    free(data);
  }

  return 0;
}

void free_packet(packet_t *packet)
{
  assert(packet != NULL);
  packet->id = 0;
  packet->size = 0;

  if (packet->data != NULL)
  {
    free(packet->data);
    packet->data = NULL;
  }

  free(packet);
}

int deserialize_message(packet_t *packet, void **message)
{
  assert(packet != NULL);
  buffer_t *buffer = NULL;
  if (packet->size > 0)
  {
    buffer = buffer_init_data(0, (const uint8_t*)packet->data, packet->size);
  }
  else
  {
    buffer = buffer_init();
  }

  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);
  switch (packet->id)
  {
    case PKT_TYPE_CONNECT_REQ:
      {
        uint32_t host_port = 0;
        if (buffer_read_uint32(buffer_iterator, &host_port))
        {
          goto packet_deserialize_fail;
        }

        char *version_number = NULL;
        if (buffer_read_string(buffer_iterator, &version_number))
        {
          goto packet_deserialize_fail;
        }

        char* version_name = NULL;
        if (buffer_read_string(buffer_iterator, &version_name))
        {
          free(version_number);
          goto packet_deserialize_fail;
        }

        uint8_t use_testnet = 0;
        if (buffer_read_uint8(buffer_iterator, &use_testnet))
        {
          free(version_number);
          free(version_name);
          goto packet_deserialize_fail;
        }

        connection_req_t *packed_message = malloc(sizeof(connection_req_t));
        assert(packed_message != NULL);
        packed_message->host_port = host_port;
        packed_message->version_number = version_number;
        packed_message->version_name = version_name;
        packed_message->use_testnet = use_testnet;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_CONNECT_RESP:
      {
        connection_resp_t *packed_message = malloc(sizeof(connection_resp_t));
        assert(packed_message != NULL);
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_PEERLIST_REQ:
      {
        get_peerlist_req_t *packed_message = malloc(sizeof(get_peerlist_req_t));
        assert(packed_message != NULL);
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_PEERLIST_RESP:
      {
        uint32_t peerlist_data_size = 0;
        if (buffer_read_uint32(buffer_iterator, &peerlist_data_size))
        {
          goto packet_deserialize_fail;
        }

        uint8_t *peerlist_data = NULL;
        if (buffer_read_bytes(buffer_iterator, &peerlist_data))
        {
          goto packet_deserialize_fail;
        }

        get_peerlist_resp_t *packed_message = malloc(sizeof(get_peerlist_resp_t));
        assert(packed_message != NULL);
        packed_message->peerlist_data_size = peerlist_data_size;
        packed_message->peerlist_data = peerlist_data;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {
        get_block_height_request_t *packed_message = malloc(sizeof(get_block_height_request_t));
        assert(packed_message != NULL);
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      {
        uint32_t height = 0;
        if (buffer_read_uint32(buffer_iterator, &height))
        {
          goto packet_deserialize_fail;
        }

        uint8_t *hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &hash))
        {
          goto packet_deserialize_fail;
        }

        get_block_height_response_t *packed_message = malloc(sizeof(get_block_height_response_t));
        assert(packed_message != NULL);
        packed_message->height = height;
        packed_message->hash = hash;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_REQ:
      {
        uint8_t *hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &hash))
        {
          goto packet_deserialize_fail;
        }

        get_block_by_hash_request_t *packed_message = malloc(sizeof(get_block_by_hash_request_t));
        assert(packed_message != NULL);
        packed_message->hash = hash;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_RESP:
      {
        uint32_t height = 0;
        if (buffer_read_uint32(buffer_iterator, &height))
        {
          goto packet_deserialize_fail;
        }

        block_t *block = NULL;
        if (deserialize_block(buffer_iterator, &block))
        {
          goto packet_deserialize_fail;
        }

        get_block_by_hash_response_t *packed_message = malloc(sizeof(get_block_by_hash_response_t));
        assert(packed_message != NULL);
        packed_message->height = height;
        packed_message->block = block;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_REQ:
      {
        uint32_t height = 0;
        if (buffer_read_uint32(buffer_iterator, &height))
        {
          goto packet_deserialize_fail;
        }

        get_block_by_height_request_t *packed_message = malloc(sizeof(get_block_by_height_request_t));
        assert(packed_message != NULL);
        packed_message->height = height;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP:
      {
        uint8_t *hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &hash))
        {
          goto packet_deserialize_fail;
        }

        block_t *block = NULL;
        if (deserialize_block(buffer_iterator, &block))
        {
          free(hash);
          goto packet_deserialize_fail;
        }

        get_block_by_height_response_t *packed_message = malloc(sizeof(get_block_by_height_response_t));
        assert(packed_message != NULL);
        packed_message->hash = hash;
        packed_message->block = block;
        *message = packed_message;
      }
      break;
    /*case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_REQ:
      {

      }
      break;
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_RESP:
      {

      }
      break;*/
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_REQ:
      {
        uint32_t height = 0;
        if (buffer_read_uint32(buffer_iterator, &height))
        {
          goto packet_deserialize_fail;
        }

        get_grouped_blocks_from_height_request_t *packed_message = malloc(sizeof(get_grouped_blocks_from_height_request_t));
        assert(packed_message != NULL);
        packed_message->height = height;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_RESP:
      {
        uint32_t block_data_size = 0;
        if (buffer_read_uint32(buffer_iterator, &block_data_size))
        {
          goto packet_deserialize_fail;
        }

        uint8_t *block_data = NULL;
        if (buffer_read_bytes(buffer_iterator, &block_data))
        {
          goto packet_deserialize_fail;
        }

        get_grouped_blocks_from_height_response_t *packed_message = malloc(sizeof(get_grouped_blocks_from_height_response_t));
        assert(packed_message != NULL);
        packed_message->block_data_size = block_data_size;
        packed_message->block_data = block_data;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ:
      {
        uint8_t *hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &hash))
        {
          goto packet_deserialize_fail;
        }

        get_block_num_transactions_request_t *packed_message = malloc(sizeof(get_block_num_transactions_request_t));
        assert(packed_message != NULL);
        packed_message->hash = hash;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP:
      {
        uint8_t *hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &hash))
        {
          goto packet_deserialize_fail;
        }

        uint64_t num_transactions = 0;
        if (buffer_read_uint64(buffer_iterator, &num_transactions))
        {
          free(hash);
          goto packet_deserialize_fail;
        }

        get_block_num_transactions_response_t *packed_message = malloc(sizeof(get_block_num_transactions_response_t));
        assert(packed_message != NULL);
        packed_message->hash = hash;
        packed_message->num_transactions = num_transactions;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ:
      {
        uint8_t *block_hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &block_hash))
        {
          goto packet_deserialize_fail;
        }

        uint8_t *tx_hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &tx_hash))
        {
          free(block_hash);
          goto packet_deserialize_fail;
        }

        get_block_transaction_by_hash_request_t *packed_message = malloc(sizeof(get_block_transaction_by_hash_request_t));
        assert(packed_message != NULL);
        packed_message->block_hash = block_hash;
        packed_message->tx_hash = tx_hash;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP:
      {
        uint8_t *block_hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &block_hash))
        {
          goto packet_deserialize_fail;
        }

        uint32_t tx_index = 0;
        if (buffer_read_uint32(buffer_iterator, &tx_index))
        {
          free(block_hash);
          goto packet_deserialize_fail;
        }

        transaction_t *transaction = NULL;
        if (deserialize_transaction(buffer_iterator, &transaction))
        {
          free(block_hash);
          goto packet_deserialize_fail;
        }

        get_block_transaction_by_hash_response_t *packed_message = malloc(sizeof(get_block_transaction_by_hash_response_t));
        assert(packed_message != NULL);
        packed_message->block_hash = block_hash;
        packed_message->tx_index = tx_index;
        packed_message->transaction = transaction;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ:
      {
        uint8_t *block_hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &block_hash))
        {
          goto packet_deserialize_fail;
        }

        uint32_t tx_index = 0;
        if (buffer_read_uint32(buffer_iterator, &tx_index))
        {
          free(block_hash);
          goto packet_deserialize_fail;
        }

        get_block_transaction_by_index_request_t *packed_message = malloc(sizeof(get_block_transaction_by_index_request_t));
        assert(packed_message != NULL);
        packed_message->block_hash = block_hash;
        packed_message->tx_index = tx_index;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP:
      {
        uint8_t *block_hash = NULL;
        if (buffer_read_bytes(buffer_iterator, &block_hash))
        {
          goto packet_deserialize_fail;
        }

        uint32_t tx_index = 0;
        if (buffer_read_uint32(buffer_iterator, &tx_index))
        {
          free(block_hash);
          goto packet_deserialize_fail;
        }

        transaction_t *transaction = NULL;
        if (deserialize_transaction(buffer_iterator, &transaction))
        {
          free(block_hash);
          goto packet_deserialize_fail;
        }

        get_block_transaction_by_index_response_t *packed_message = malloc(sizeof(get_block_transaction_by_index_response_t));
        assert(packed_message != NULL);
        packed_message->block_hash = block_hash;
        packed_message->tx_index = tx_index;
        packed_message->transaction = transaction;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION:
      {
        transaction_t *transaction = NULL;
        if (deserialize_transaction(buffer_iterator, &transaction))
        {
          goto packet_deserialize_fail;
        }

        incoming_mempool_transaction_t *packed_message = malloc(sizeof(incoming_mempool_transaction_t));
        assert(packed_message != NULL);
        packed_message->transaction = transaction;
        *message = packed_message;
      }
      break;
    default:
      LOG_DEBUG("Could not deserialize packet with unknown packet id: %u!", packet->id);
      goto packet_deserialize_fail;
  }

  // check to see if there is any extraneous data in the buffer
  uint32_t remaining_size = buffer_get_remaining_size(buffer_iterator);
  if (remaining_size > 0)
  {
    LOG_ERROR("Could not deserialize packet with id: %u, packet has extraneous data of size: %u!", packet->id, remaining_size);
    free_message(packet->id, 1, *message);
    goto packet_deserialize_fail;
  }

  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);
  return 0;

packet_deserialize_fail:
  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);
  return 1;
}

int serialize_message(packet_t **packet, uint32_t packet_id, va_list args)
{
  buffer_t *buffer = buffer_init();
  switch (packet_id)
  {
    case PKT_TYPE_CONNECT_REQ:
      {
        uint32_t host_port = va_arg(args, uint32_t);
        uint8_t use_testnet = va_arg(args, int);
        buffer_write_uint32(buffer, host_port);
        buffer_write_string(buffer, APPLICATION_VERSION, strlen(APPLICATION_VERSION));
        buffer_write_string(buffer, APPLICATION_RELEASE_NAME, strlen(APPLICATION_RELEASE_NAME));
        buffer_write_uint8(buffer, use_testnet);
      }
      break;
    case PKT_TYPE_CONNECT_RESP:
      {

      }
      break;
    case PKT_TYPE_GET_PEERLIST_REQ:
      {

      }
      break;
    case PKT_TYPE_GET_PEERLIST_RESP:
      {
        buffer_t *peerlist_buffer = va_arg(args, buffer_t*);
        assert(peerlist_buffer != NULL);

        uint32_t peerlist_data_size = buffer_get_size(peerlist_buffer);
        assert(peerlist_data_size <= UINT32_MAX);

        uint8_t *peerlist_data = buffer_get_data(peerlist_buffer);
        assert(peerlist_data != NULL);

        buffer_write_uint32(buffer, peerlist_data_size);
        buffer_write_bytes(buffer, peerlist_data, peerlist_data_size);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {

      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      {
        uint32_t height = va_arg(args, uint32_t);
        uint8_t *hash = va_arg(args, uint8_t*);
        assert(hash != NULL);

        buffer_write_uint32(buffer, height);
        buffer_write_bytes(buffer, hash, HASH_SIZE);
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_REQ:
      {
        uint8_t *hash = va_arg(args, uint8_t*);
        assert(hash != NULL);

        buffer_write_bytes(buffer, hash, HASH_SIZE);
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_RESP:
      {
        uint32_t height = va_arg(args, uint32_t);
        block_t *block = va_arg(args, block_t*);
        assert(block != NULL);

        buffer_write_uint32(buffer, height);
        serialize_block(buffer, block);
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_REQ:
      {
        uint32_t height = va_arg(args, uint32_t);
        buffer_write_uint32(buffer, height);
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP:
      {
        uint8_t *hash = va_arg(args, uint8_t*);
        block_t *block = va_arg(args, block_t*);

        assert(hash != NULL);
        assert(block != NULL);

        buffer_write_bytes(buffer, hash, HASH_SIZE);
        serialize_block(buffer, block);
      }
      break;
    /*case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_REQ:
      {

      }
      break;
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_RESP:
      {

      }
      break;*/
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_REQ:
      {
        uint32_t height = va_arg(args, uint32_t);
        buffer_write_uint32(buffer, height);
      }
      break;
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_RESP:
      {
        buffer_t *block_data_buffer = va_arg(args, buffer_t*);
        assert(block_data_buffer != NULL);

        uint32_t block_data_size = buffer_get_size(block_data_buffer);
        assert(block_data_size <= UINT32_MAX);

        uint8_t *block_data = buffer_get_data(block_data_buffer);
        assert(block_data != NULL);

        buffer_write_uint32(buffer, block_data_size);
        buffer_write_bytes(buffer, block_data, block_data_size);
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ:
      {
        uint8_t *hash = va_arg(args, uint8_t*);
        assert(hash != NULL);

        buffer_write_bytes(buffer, hash, HASH_SIZE);
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP:
      {
        uint8_t *hash = va_arg(args, uint8_t*);
        uint64_t num_transactions = va_arg(args, uint64_t);
        assert(hash != NULL);

        buffer_write_bytes(buffer, hash, HASH_SIZE);
        buffer_write_uint64(buffer, num_transactions);
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ:
      {
        uint8_t *block_hash = va_arg(args, uint8_t*);
        uint8_t *tx_hash = va_arg(args, uint8_t*);

        assert(block_hash != NULL);
        assert(tx_hash != NULL);

        buffer_write_bytes(buffer, block_hash, HASH_SIZE);
        buffer_write_bytes(buffer, tx_hash, HASH_SIZE);
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP:
      {
        uint8_t *block_hash = va_arg(args, uint8_t*);
        uint32_t tx_index = va_arg(args, uint32_t);
        transaction_t *transaction = va_arg(args, transaction_t*);

        assert(block_hash != NULL);
        assert(transaction != NULL);

        buffer_write_bytes(buffer, block_hash, HASH_SIZE);
        buffer_write_uint32(buffer, tx_index);
        serialize_transaction(buffer, transaction);
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ:
      {
        uint8_t *block_hash = va_arg(args, uint8_t*);
        uint32_t tx_index = va_arg(args, uint32_t);
        assert(block_hash != NULL);

        buffer_write_bytes(buffer, block_hash, HASH_SIZE);
        buffer_write_uint32(buffer, tx_index);
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP:
      {
        uint8_t *block_hash = va_arg(args, uint8_t*);
        uint32_t tx_index = va_arg(args, uint32_t);
        transaction_t *transaction = va_arg(args, transaction_t*);

        assert(block_hash != NULL);
        assert(transaction != NULL);

        buffer_write_bytes(buffer, block_hash, HASH_SIZE);
        buffer_write_uint32(buffer, tx_index);
        serialize_transaction(buffer, transaction);
      }
      break;
    case PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION:
      {
        transaction_t *transaction = va_arg(args, transaction_t*);
        assert(transaction != NULL);

        serialize_transaction(buffer, transaction);
      }
      break;
    default:
      LOG_DEBUG("Could not serialize packet with unknown packet id: %u!", packet_id);
      return 1;
  }

  uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  packet_t *serialized_packet = make_packet();
  serialized_packet->id = packet_id;
  serialized_packet->size = data_len;
  if (data_len > 0)
  {
    serialized_packet->data = malloc(data_len);
    assert(serialized_packet->data != NULL);
    memcpy(serialized_packet->data, data, data_len);
  }

  *packet = serialized_packet;
  buffer_free(buffer);
  return 0;
}

void free_message(uint32_t packet_id, int did_packet_fail, void *message_object)
{
  assert(message_object != NULL);
  switch (packet_id)
  {
    case PKT_TYPE_CONNECT_REQ:
      {
        connection_req_t *message = (connection_req_t*)message_object;
        free(message->version_number);
        free(message->version_name);
        free(message);
      }
      break;
    case PKT_TYPE_CONNECT_RESP:
      {
        connection_resp_t *message = (connection_resp_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_PEERLIST_REQ:
      {
        get_peerlist_req_t *message = (get_peerlist_req_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_PEERLIST_RESP:
      {
        get_peerlist_resp_t *message = (get_peerlist_resp_t*)message_object;
        free(message->peerlist_data);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {
        get_block_height_request_t *message = (get_block_height_request_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      {
        get_block_height_response_t *message = (get_block_height_response_t*)message_object;
        free(message->hash);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_REQ:
      {
        get_block_by_hash_request_t *message = (get_block_by_hash_request_t*)message_object;
        free(message->hash);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_RESP:
      {
        get_block_by_hash_response_t *message = (get_block_by_hash_response_t*)message_object;
        if (did_packet_fail)
        {
          free_block(message->block);
        }

        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_REQ:
      {
        get_block_by_height_request_t *message = (get_block_by_height_request_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP:
      {
        get_block_by_height_response_t *message = (get_block_by_height_response_t*)message_object;
        free(message->hash);
        if (did_packet_fail)
        {
          free_block(message->block);
        }

        free(message);
      }
      break;
    /*case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_REQ:
      {

      }
      break;
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_RESP:
      {

      }
      break;*/
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_REQ:
      {
        get_grouped_blocks_from_height_request_t *message = (get_grouped_blocks_from_height_request_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_RESP:
      {
        get_grouped_blocks_from_height_response_t *message = (get_grouped_blocks_from_height_response_t*)message_object;
        free(message->block_data);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ:
      {
        get_block_num_transactions_request_t *message = (get_block_num_transactions_request_t*)message_object;
        free(message->hash);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP:
      {
        get_block_num_transactions_response_t *message = (get_block_num_transactions_response_t*)message_object;
        free(message->hash);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ:
      {
        get_block_transaction_by_hash_request_t *message = (get_block_transaction_by_hash_request_t*)message_object;
        free(message->block_hash);
        free(message->tx_hash);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP:
      {
        get_block_transaction_by_hash_response_t *message = (get_block_transaction_by_hash_response_t*)message_object;
        free(message->block_hash);
        if (did_packet_fail)
        {
          free_transaction(message->transaction);
        }

        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ:
      {
        get_block_transaction_by_index_request_t *message = (get_block_transaction_by_index_request_t*)message_object;
        free(message->block_hash);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP:
      {
        get_block_transaction_by_index_response_t *message = (get_block_transaction_by_index_response_t*)message_object;
        free(message->block_hash);
        if (did_packet_fail)
        {
          free_transaction(message->transaction);
        }

        free(message);
      }
      break;
    case PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION:
      {
        incoming_mempool_transaction_t *message = (incoming_mempool_transaction_t*)message_object;
        free_transaction(message->transaction);
        free(message);
      }
      break;
    default:
      LOG_DEBUG("Could not free packet with unknown packet id: %u!", packet_id);
      break;
  }
}

net_connection_t* get_sync_net_connection(void)
{
  return g_protocol_sync_entry.net_connection;
}

int get_sync_initiated(void)
{
  return g_protocol_sync_entry.sync_initiated;
}

int init_sync_request(int height, net_connection_t *net_connection)
{
  if (g_protocol_sync_entry.sync_initiated)
  {
    return 1;
  }

  g_protocol_sync_entry.net_connection = net_connection;

  g_protocol_sync_entry.sync_initiated = 1;
  g_protocol_sync_entry.sync_did_backup_blockchain = 0;
  g_protocol_sync_entry.sync_finding_top_block = 0;
  g_protocol_sync_entry.sync_pending_block = NULL;
  g_protocol_sync_entry.sync_height = height;
  g_protocol_sync_entry.sync_start_height = -1;

  g_protocol_sync_entry.is_syncing_grouped_blocks = 0;
  vec_init(&g_protocol_sync_entry.sync_pending_blocks);
  g_protocol_sync_entry.sync_pending_blocks_count = 0;

  g_protocol_sync_entry.last_sync_height = 0;
  g_protocol_sync_entry.last_sync_ts = 0;
  g_protocol_sync_entry.last_sync_tries = 0;

  g_protocol_sync_entry.tx_sync_initiated = 0;
  g_protocol_sync_entry.tx_sync_num_txs = 0;
  g_protocol_sync_entry.last_tx_sync_index = -1;
  g_protocol_sync_entry.last_tx_sync_ts = 0;
  g_protocol_sync_entry.last_tx_sync_tries = 0;
  return 0;
}

int clear_sync_request(int sync_success)
{
  if (g_protocol_sync_entry.sync_initiated == 0)
  {
    return 1;
  }

  if (sync_success == 0 && g_protocol_sync_entry.sync_did_backup_blockchain)
  {
    if (restore_blockchain() == 0)
    {
      LOG_INFO("Successfully restored blockchain.");
    }
    else
    {
      LOG_WARNING("Could not restore blockchain after sync to alternative blockchain failed!");
    }
  }

  g_protocol_sync_entry.net_connection = NULL;

  g_protocol_sync_entry.sync_initiated = 0;
  g_protocol_sync_entry.sync_did_backup_blockchain = 0;
  g_protocol_sync_entry.sync_finding_top_block = 0;

  g_protocol_sync_entry.sync_height = 0;
  g_protocol_sync_entry.sync_start_height = -1;

  g_protocol_sync_entry.is_syncing_grouped_blocks = 0;
  vec_deinit(&g_protocol_sync_entry.sync_pending_blocks);
  g_protocol_sync_entry.sync_pending_blocks_count = 0;

  g_protocol_sync_entry.last_sync_height = 0;
  g_protocol_sync_entry.last_sync_ts = 0;
  g_protocol_sync_entry.last_sync_tries = 0;

  g_protocol_sync_entry.tx_sync_initiated = 0;
  g_protocol_sync_entry.tx_sync_num_txs = 0;
  g_protocol_sync_entry.last_tx_sync_index = -1;
  g_protocol_sync_entry.last_tx_sync_ts = 0;
  g_protocol_sync_entry.last_tx_sync_tries = 0;

  handle_sync_stopped();
  return 0;
}

int clear_tx_sync_request(void)
{
  if (g_protocol_sync_entry.sync_initiated == 0 || g_protocol_sync_entry.tx_sync_initiated == 0)
  {
    return 1;
  }

  g_protocol_sync_entry.tx_sync_initiated = 0;
  g_protocol_sync_entry.tx_sync_num_txs = 0;
  g_protocol_sync_entry.last_tx_sync_index = -1;
  g_protocol_sync_entry.last_tx_sync_ts = 0;
  g_protocol_sync_entry.last_tx_sync_tries = 0;
  return 0;
}

int clear_grouped_sync_request(void)
{
  if (g_protocol_sync_entry.sync_initiated == 0)
  {
    return 1;
  }

  g_protocol_sync_entry.sync_pending_block = NULL;
  g_protocol_sync_entry.is_syncing_grouped_blocks = 0;
  vec_init(&g_protocol_sync_entry.sync_pending_blocks);
  g_protocol_sync_entry.sync_pending_blocks_count = 0;
  return 0;
}

void handle_sync_started(void)
{
  if (get_is_miner_initialized())
  {
    LOG_INFO("Syncronization in progress, pausing miner worker threads...");
    set_workers_paused(1);
  }
}

void handle_sync_added_block(void)
{
  float sync_progress_percentage = ((float)g_protocol_sync_entry.last_sync_height / (float)g_protocol_sync_entry.sync_height) * 100;
  LOG_INFO("Received block at height: %u/%u block(s) remaining (%.2f%% complete)", g_protocol_sync_entry.last_sync_height, g_protocol_sync_entry.sync_height, sync_progress_percentage);
}

void handle_sync_stopped(void)
{

}

void handle_sync_completed(void)
{
  if (get_workers_paused())
  {
    LOG_INFO("Syncronization completed, resuming miner worker threads...");
    set_workers_paused(0);
  }
}

int check_sync_status(int force_sync_complete)
{
  uint32_t current_block_height = get_block_height();
  if (current_block_height > 0 && (current_block_height >= g_protocol_sync_entry.sync_height || force_sync_complete))
  {
    if (clear_sync_request(1) == 0)
    {
      LOG_INFO("Successfully synchronized blockchain at block height: %u", current_block_height);
      handle_sync_completed();
      return 0;
    }
  }

  return 1;
}

int request_sync_block(net_connection_t *net_connection, uint32_t height, uint8_t *hash)
{
  int32_t sync_height = height;
  if (hash != NULL)
  {
    sync_height = get_block_height_from_hash(hash);
  }

  if (sync_height < 0)
  {
    LOG_ERROR("Could not request block at an unknown sync height!");
    return 1;
  }

  if (g_protocol_sync_entry.last_sync_tries > RESYNC_BLOCK_MAX_TRIES)
  {
    assert(clear_sync_request(0) == 0);
    LOG_WARNING("Timed out when trying to request block at height: %u!", sync_height);
    return 1;
  }

  if (hash != NULL)
  {
    if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_BY_HASH_REQ, hash))
    {
      return 1;
    }
  }
  else
  {
    if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_BY_HEIGHT_REQ, height))
    {
      return 1;
    }
  }

  if (sync_height == g_protocol_sync_entry.last_sync_height)
  {
    g_protocol_sync_entry.last_sync_tries++;
  }
  else
  {
    g_protocol_sync_entry.last_sync_tries = 0;
    g_protocol_sync_entry.last_sync_height = sync_height;
  }

  g_protocol_sync_entry.last_sync_ts = get_current_time();
  return 0;
}

int request_sync_next_block(net_connection_t *net_connection)
{
  assert(net_connection != NULL);
  uint32_t block_height = g_protocol_sync_entry.last_sync_height;
  if (has_block_by_height(block_height) == 0)
  {
    LOG_ERROR("Cannot request next block when previous block at height: %u, was not found in the blockchain!", block_height);
    return 1;
  }

  uint32_t sync_height = g_protocol_sync_entry.last_sync_height + 1;
  if (sync_height == g_protocol_sync_entry.last_sync_height)
  {
    g_protocol_sync_entry.last_sync_tries++;
  }
  else
  {
    g_protocol_sync_entry.last_sync_tries = 0;
    g_protocol_sync_entry.last_sync_height = sync_height;
  }

  g_protocol_sync_entry.last_sync_ts = get_current_time();
  if (g_protocol_sync_entry.sync_pending_blocks_count == 0)
  {
    if (handle_packet_sendto(net_connection, PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_REQ, sync_height))
    {
      return 1;
    }
  }
  else
  {
    block_t *pending_block = (block_t*)vec_pop(&g_protocol_sync_entry.sync_pending_blocks);
    assert(pending_block != NULL);
    g_protocol_sync_entry.sync_pending_blocks_count--;
    return block_header_received(net_connection, pending_block);
  }

  return 0;
}

int request_sync_transaction(net_connection_t *net_connection, uint8_t *block_hash, uint32_t tx_index, uint8_t *tx_hash)
{
  assert(net_connection != NULL);
  assert(block_hash != NULL);

  if (tx_hash != NULL)
  {
    if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ, block_hash, tx_hash))
    {
      return 1;
    }
  }
  else
  {
    if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ, block_hash, tx_index))
    {
      return 1;
    }
  }

  if (tx_index == g_protocol_sync_entry.last_tx_sync_index)
  {
    g_protocol_sync_entry.last_tx_sync_tries++;
  }
  else
  {
    g_protocol_sync_entry.last_tx_sync_tries = 0;
    g_protocol_sync_entry.last_tx_sync_index = tx_index;
  }

  g_protocol_sync_entry.last_tx_sync_ts = get_current_time();
  return 0;
}

int request_sync_next_transaction(net_connection_t *net_connection)
{
  assert(net_connection != NULL);
  block_t *pending_block = g_protocol_sync_entry.sync_pending_block;
  assert(pending_block != NULL);

  uint32_t tx_sync_index = g_protocol_sync_entry.last_tx_sync_index + 1;
  if (tx_sync_index > pending_block->transaction_count)
  {
    return 1;
  }

  return request_sync_transaction(net_connection, pending_block->hash, tx_sync_index, NULL);
}

int request_sync_previous_block(net_connection_t *net_connection)
{
  uint32_t sync_height = g_protocol_sync_entry.last_sync_height - 1;
  return request_sync_block(net_connection, sync_height, NULL);
}

int block_header_received(net_connection_t *net_connection, block_t *block)
{
  assert(net_connection != NULL);
  assert(block != NULL);
  if (g_protocol_sync_entry.sync_initiated)
  {
    int has_checkpoint = has_checkpoint_hash_by_height(g_protocol_sync_entry.last_sync_height);
    if (has_checkpoint)
    {
      uint8_t *checkpoint_hash = NULL;
      assert(get_checkpoint_hash_from_height(g_protocol_sync_entry.last_sync_height, &checkpoint_hash) == 0);
      assert(checkpoint_hash != NULL);

      if (compare_block_hash(block->hash, checkpoint_hash) == 0)
      {
        char *checkpoint_hash_str = bin2hex(checkpoint_hash, HASH_SIZE);
        char *block_hash_str = bin2hex(block->hash, HASH_SIZE);
        LOG_ERROR("Failed to receive block header, found checkpoint at height: %u, block received: %s "
          "does not match checkpoint hash: %s!", g_protocol_sync_entry.last_sync_height, checkpoint_hash_str, block_hash_str);

        free(checkpoint_hash_str);
        free(block_hash_str);

        // since we failed to get the correct hash corresponding to the
        // predefined checkpoint hash, clear this sync request...
        assert(clear_sync_request(0) == 0);
        return 1;
      }
    }

    if (g_protocol_sync_entry.sync_start_height == -1)
    {
      if (g_protocol_sync_entry.sync_finding_top_block == 0)
      {
        g_protocol_sync_entry.last_sync_height = get_block_height();
        g_protocol_sync_entry.sync_finding_top_block = 1;
      }

      int found_starting_block = has_block_by_hash(block->hash);
      int can_rollback_and_resync = 0;
      if (found_starting_block)
      {
        // check the block's actual height in our blockchain to make sure
        // the height corresponds with the last sync height we've counted...
        /*uint32_t actual_height = get_block_height_from_hash(block->hash);
        if (actual_height != g_protocol_sync_entry.last_sync_height)
        {
          char *block_hash_str = bin2hex(block->hash, HASH_SIZE);
          LOG_ERROR("Failed to receive block header, found starting block: %s with unexpected height: %u, expected block at height: %u!",
            block_hash_str, actual_height, g_protocol_sync_entry.last_sync_height);

          free(block_hash_str);
          assert(clear_sync_request(0) == 0);
          return 1;
        }*/

        LOG_INFO("Found sync starting block at height: %u!", g_protocol_sync_entry.last_sync_height);
        g_protocol_sync_entry.sync_start_height = g_protocol_sync_entry.last_sync_height;
        can_rollback_and_resync = 1;
      }
      else if (g_protocol_sync_entry.last_sync_height <= 1)
      {
        LOG_WARNING("Unable to find sync starting height, continuing anyway...");
        g_protocol_sync_entry.sync_start_height = 0;
        can_rollback_and_resync = 1;
      }
      else
      {
        if (request_sync_previous_block(net_connection))
        {
          assert(clear_sync_request(0) == 0);
          return 1;
        }
      }

      if (can_rollback_and_resync)
      {
        g_protocol_sync_entry.sync_finding_top_block = 0;
        if (backup_blockchain_and_rollback())
        {
          // if by some way we fail to rollback and resync and we
          // fail to clear our sync request, then throw an assertion,
          // this should never happen...
          assert(clear_sync_request(0) == 0);
          return 1;
        }

        assert(clear_grouped_sync_request() == 0);
        g_protocol_sync_entry.last_sync_height = g_protocol_sync_entry.sync_start_height;
        if (request_sync_next_block(g_protocol_sync_entry.net_connection))
        {
          return 1;
        }
      }
    }
    else if (g_protocol_sync_entry.tx_sync_initiated == 0)
    {
      block->transaction_count = 0;
      block->transactions = NULL;
      if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ, block->hash))
      {
        // we failed to request transactions for this block header,
        // clear the sync request in attempt to resync this block later...
        assert(clear_sync_request(0) == 0);
        return 1;
      }

      g_protocol_sync_entry.sync_pending_block = block;
    }
  }

  return 0;
}

int block_header_sync_complete(net_connection_t *net_connection, block_t *block)
{
  assert(net_connection != NULL);
  assert(block != NULL);
  if (validate_and_insert_block(block) == 0)
  {
    handle_sync_added_block();
    if (check_sync_status(0))
    {
      if (request_sync_next_block(g_protocol_sync_entry.net_connection))
      {
        return 1;
      }
    }

    return 0;
  }

  return 1;
}

int transaction_received(net_connection_t *net_connection, transaction_t *transaction, uint32_t tx_index)
{
  assert(net_connection != NULL);
  assert(transaction != NULL);

  if (g_protocol_sync_entry.sync_initiated && g_protocol_sync_entry.tx_sync_initiated)
  {
    block_t *pending_block = g_protocol_sync_entry.sync_pending_block;
    assert(pending_block != NULL);

    assert(add_transaction_to_block(pending_block, transaction, tx_index) == 0);
    if (tx_index + 1 < g_protocol_sync_entry.tx_sync_num_txs)
    {
      if (request_sync_next_transaction(net_connection))
      {
        assert(clear_sync_request(0) == 0);
        return 1;
      }
    }
    else
    {
      // compute the block's merkle root again and compare it against
      // the block's currently defined merkle root to see if
      // this block does infact have the correct transactions it requires...
      if (valid_merkle_root(pending_block))
      {
        // must clear the tx sync entry cache before calling block_header_sync_complete,
        // otherwise the entire sync entry cache will be cleared and this assertion will fail...
        assert(clear_tx_sync_request() == 0);
        if (block_header_sync_complete(net_connection, pending_block))
        {
          // we failed to add this block when trying to switch to it's
          // alternative chain, restore our previous working chain instead.
          assert(clear_sync_request(0) == 0);
          return 1;
        }
      }
      else
      {
        assert(clear_sync_request(0) == 0);
        return 1;
      }
    }
  }

  return 0;
}

int backup_blockchain_and_rollback(void)
{
  uint32_t current_block_height = get_block_height();
  if (current_block_height > 0)
  {
    LOG_INFO("Backing up blockchain in preparation for resync...");
    if (backup_blockchain())
    {
      return 1;
    }

    g_protocol_sync_entry.sync_did_backup_blockchain = 1;
    if (current_block_height > g_protocol_sync_entry.sync_start_height)
    {
      LOG_INFO("Rolling blockchain back to height: %u...", g_protocol_sync_entry.sync_start_height);
      if (rollback_blockchain(g_protocol_sync_entry.sync_start_height))
      {
        return 1;
      }
    }
  }

  return 0;
}

int can_packet_be_processed(net_connection_t *net_connection, uint32_t packet_id)
{
  int check_sender = 0;
  switch (packet_id)
  {
    case PKT_TYPE_CONNECT_REQ:
    case PKT_TYPE_CONNECT_RESP:
      return 1;

    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      return 1;

    case PKT_TYPE_GET_BLOCK_BY_HASH_REQ:
      return 1;
    case PKT_TYPE_GET_BLOCK_BY_HASH_RESP:
      check_sender = 1;
      break;

    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_REQ:
      return 1;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP:
      check_sender = 1;
      break;

    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_REQ:
      return 1;
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_RESP:
      check_sender = 1;
      break;

    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ:
      return 1;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP:
      check_sender = 1;
      break;

    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ:
      return 1;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP:
      check_sender = 1;
      break;

    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ:
      return 1;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP:
      check_sender = 1;
      break;

    case PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION:
      return 1;
    default:
      break;
  }

  // check the sender of the message, this would be used when we are expecting
  // a syncronization message back from the node we have established a sync request with locally...
  if (check_sender)
  {
    if (net_connection != g_protocol_sync_entry.net_connection)
    {
      return 0;
    }
  }

  return 1;
}

int handle_packet_anonymous(net_connection_t *net_connection, uint32_t packet_id, void *message_object)
{
  assert(net_connection != NULL);
  assert(message_object != NULL);
  switch (packet_id)
  {
    case PKT_TYPE_CONNECT_REQ:
      {
        connection_req_t *message = (connection_req_t*)message_object;
        net_connection->host_port = message->host_port;
        net_connection->anonymous = 0;

        struct mg_connection *connection = net_connection->connection;
        assert(connection != NULL);

        uint32_t remote_ip = ntohl(*(uint32_t*)&connection->sa.sin.sin_addr);
        uint64_t peer_id = concatenate(remote_ip, message->host_port);
        if (has_peer(peer_id))
        {
          LOG_DEBUG("Cannot add an already existant peer with id: %u!", peer_id);
          return 1;
        }

        if (g_protocol_force_version_check)
        {
          if (memcmp(message->version_number, APPLICATION_VERSION, strlen(APPLICATION_VERSION)) != 0)
          {
            LOG_DEBUG("Failed to verify version number: [%s] expected: [%s], for peer with id: [%" PRIu64 "]!\n", message->version_number, APPLICATION_VERSION, peer_id);
            return 1;
          }

          if (memcmp(message->version_name, APPLICATION_RELEASE_NAME, strlen(APPLICATION_RELEASE_NAME)) != 0)
          {
            LOG_DEBUG("Failed to verify version name: [%s] expected: [%s], for peer with id: [%" PRIu64 "]!\n", message->version_name, APPLICATION_RELEASE_NAME, peer_id);
            return 1;
          }
        }

        // check to see if the peer is connected to the right network,
        // that's appropriate to what mode they are running in...
        if (message->use_testnet != parameters_get_use_testnet())
        {
          return 1;
        }

        peer_t *peer = init_peer(peer_id, net_connection);
        assert(add_peer(peer) == 0);

        if (handle_packet_sendto(net_connection, PKT_TYPE_CONNECT_RESP))
        {
          free_peer(peer);
          return 1;
        }

        return 0;
      }
      break;
    case PKT_TYPE_CONNECT_RESP:
      {
        connection_resp_t *message = (connection_resp_t*)message_object;
        net_connection->anonymous = 0;
        return 0;
      }
      break;
    default:
      assert(close_net_connection(net_connection) == 0);
      return 1;
  }

  return 1;
}

int handle_packet(net_connection_t *net_connection, uint32_t packet_id, void *message_object)
{
  assert(net_connection != NULL);
  assert(message_object != NULL);
  switch (packet_id)
  {
    case PKT_TYPE_GET_PEERLIST_REQ:
      {
        get_peerlist_req_t *message = (get_peerlist_req_t*)message_object;
        buffer_t *buffer = buffer_init();
        if (serialize_peerlist(buffer))
        {
          buffer_free(buffer);
          return 1;
        }

        if (handle_packet_sendto(net_connection, PKT_TYPE_GET_PEERLIST_RESP, buffer))
        {
          buffer_free(buffer);
          return 1;
        }

        buffer_free(buffer);
        return 0;
      }
      break;
    case PKT_TYPE_GET_PEERLIST_RESP:
      {
        get_peerlist_resp_t *message = (get_peerlist_resp_t*)message_object;
        buffer_t *buffer = buffer_init_data(0, message->peerlist_data, message->peerlist_data_size);
        buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);
        if (deserialize_peerlist(buffer_iterator))
        {
          buffer_iterator_free(buffer_iterator);
          buffer_free(buffer);
          return 1;
        }

        buffer_iterator_free(buffer_iterator);
        buffer_free(buffer);
        return 0;
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {
        get_block_height_request_t *message = (get_block_height_request_t*)message_object;
        if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_HEIGHT_RESP,
          get_block_height(), get_current_block_hash()))
        {
          return 1;
        }

        return 0;
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      {
        get_block_height_response_t *message = (get_block_height_response_t*)message_object;
        int can_initiate_sync = 1;
        uint32_t current_block_height = get_block_height();
        if (message->height > current_block_height)
        {
          if (g_protocol_sync_entry.sync_initiated)
          {
            if (g_protocol_sync_entry.net_connection == net_connection)
            {
              if (message->height > g_protocol_sync_entry.sync_height)
              {
                LOG_INFO("Updating sync height with presumed top block: %u...", message->height);
                g_protocol_sync_entry.sync_height = message->height;
              }

              can_initiate_sync = 0;
            }

            if (g_protocol_sync_entry.sync_did_backup_blockchain)
            {
              can_initiate_sync = 0;
            }
          }

          if (can_initiate_sync)
          {
            LOG_INFO("Found potential alternative blockchain at height: %u", message->height);
            clear_sync_request(0);

            if (init_sync_request(message->height, net_connection) == 0)
            {
              if (current_block_height > 0)
              {
                LOG_INFO("Determining best synchronization starting height...");
                g_protocol_sync_entry.last_sync_height = current_block_height + 1;
                if (request_sync_previous_block(net_connection))
                {
                  LOG_ERROR("Failed to request previous block when looking for synchronization starting height!");
                  assert(clear_sync_request(0) == 0);
                  return 1;
                }
              }
              else
              {
                g_protocol_sync_entry.sync_start_height = 0;
                LOG_INFO("Beginning sync with presumed top block: %u...", message->height);
                if (request_sync_next_block(net_connection))
                {
                  LOG_ERROR("Failed to request next block when looking for synchronization starting height!");
                  assert(clear_sync_request(0) == 0);
                  return 1;
                }
              }

              handle_sync_started();
            }
          }
        }

        return 0;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_REQ:
      {
        get_block_by_hash_request_t *message = (get_block_by_hash_request_t*)message_object;
        block_t *block = get_block_from_hash(message->hash);
        if (block != NULL)
        {
          uint32_t block_height = get_block_height_from_block(block);
          if (block_height > 0)
          {
            if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_BY_HASH_RESP, block_height, block))
            {
              free_block(block);
              return 1;
            }
          }

          free_block(block);
        }

        return 0;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_RESP:
      {
        get_block_by_hash_response_t *message = (get_block_by_hash_response_t*)message_object;
        if (g_protocol_sync_entry.sync_initiated || g_protocol_sync_entry.sync_finding_top_block)
        {
          if (block_header_received(net_connection, message->block))
          {
            return 1;
          }

          return 0;
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_REQ:
      {
        get_block_by_height_request_t *message = (get_block_by_height_request_t*)message_object;
        if (message->height > 0)
        {
          block_t *block = get_block_from_height(message->height);
          if (block != NULL)
          {
            if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP, block->hash, block))
            {
              free_block(block);
              return 1;
            }

            free_block(block);
          }

          return 0;
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP:
      {
        get_block_by_height_response_t *message = (get_block_by_height_response_t*)message_object;
        if (g_protocol_sync_entry.sync_initiated || g_protocol_sync_entry.sync_finding_top_block)
        {
          if (block_header_received(net_connection, message->block))
          {
            return 1;
          }

          return 0;
        }
      }
      break;
    /*case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_REQ:
      {

      }
      break;
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_RESP:
      {

      }
      break;*/
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_REQ:
      {
        get_grouped_blocks_from_height_request_t *message = (get_grouped_blocks_from_height_request_t*)message_object;
        uint32_t current_block_height = get_block_height();
        if (message->height <= current_block_height)
        {
          buffer_t *block_data_buffer = buffer_init();
          uint32_t blocks_count = 0;
          uint32_t top_block_height = MIN(message->height + MAX_GROUPED_BLOCKS_COUNT, current_block_height);
          for (uint32_t i = top_block_height - 1; i >= message->height; i--)
          {
            block_t *block = get_block_from_height(i);
            assert(block != NULL);

            serialize_block(block_data_buffer, block);
            blocks_count++;
            free_block(block);
          }

          if (blocks_count == 0)
          {
            buffer_free(block_data_buffer);
            return 1;
          }

          uint8_t *block_data = buffer_get_data(block_data_buffer);
          size_t block_data_size = buffer_get_size(block_data_buffer);

          buffer_t *buffer = buffer_init();
          buffer_write_uint32(buffer, blocks_count);
          buffer_write(buffer, block_data, block_data_size);

          if (handle_packet_sendto(net_connection, PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_RESP, buffer))
          {
            buffer_free(block_data_buffer);
            buffer_free(buffer);
            return 1;
          }

          buffer_free(block_data_buffer);
          buffer_free(buffer);
          return 0;
        }
      }
      break;
    case PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_RESP:
      {
        get_grouped_blocks_from_height_response_t *message = (get_grouped_blocks_from_height_response_t*)message_object;
        if (g_protocol_sync_entry.sync_initiated && g_protocol_sync_entry.sync_pending_blocks_count == 0)
        {
          buffer_t *buffer = buffer_init_data(0, message->block_data, message->block_data_size);
          buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);
          uint32_t blocks_count = 0;
          if (buffer_read_uint32(buffer_iterator, &blocks_count))
          {
            buffer_free(buffer);
            buffer_iterator_free(buffer_iterator);
            return 1;
          }

          if (blocks_count == 0)
          {
            LOG_DEBUG("Got grouped block response with no blocks!");
            buffer_free(buffer);
            buffer_iterator_free(buffer_iterator);
            return 1;
          }
          else if (blocks_count > MAX_GROUPED_BLOCKS_COUNT)
          {
            LOG_DEBUG("Got grouped block response with blocks count: %u greater than allowed: %u!", blocks_count, MAX_GROUPED_BLOCKS_COUNT);
            buffer_free(buffer);
            buffer_iterator_free(buffer_iterator);
            return 1;
          }

          // blocks are sent in the reverse order and deserialized, placed in the
          // queue in the correct order pushing the last block right and pulling
          // the blocks from the queue left to right until the queue is empty...
          for (uint32_t i = 0; i < blocks_count; i++)
          {
            block_t *block = NULL;
            if (deserialize_block(buffer_iterator, &block))
            {
              buffer_free(buffer);
              buffer_iterator_free(buffer_iterator);
              return 1;
            }

            assert(block != NULL);
            assert(vec_push(&g_protocol_sync_entry.sync_pending_blocks, block) == 0);
            g_protocol_sync_entry.sync_pending_blocks_count++;
          }

          block_t *pending_block = (block_t*)vec_pop(&g_protocol_sync_entry.sync_pending_blocks);
          assert(pending_block != NULL);
          g_protocol_sync_entry.sync_pending_blocks_count--;
          if (block_header_received(net_connection, pending_block))
          {
            buffer_free(buffer);
            buffer_iterator_free(buffer_iterator);
            return 1;
          }

          buffer_free(buffer);
          buffer_iterator_free(buffer_iterator);
          return 0;
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ:
      {
        get_block_num_transactions_request_t *message = (get_block_num_transactions_request_t*)message_object;
        block_t *block = get_block_from_hash(message->hash);
        if (block != NULL)
        {
          if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP,
            block->hash, block->transaction_count))
          {
            free_block(block);
            return 1;
          }

          free_block(block);
          return 0;
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP:
      {
        get_block_num_transactions_response_t *message = (get_block_num_transactions_response_t*)message_object;
        if (g_protocol_sync_entry.sync_initiated && g_protocol_sync_entry.tx_sync_initiated == 0 &&
            g_protocol_sync_entry.sync_pending_block != NULL)
        {
          block_t *pending_block = g_protocol_sync_entry.sync_pending_block;
          if (pending_block == NULL)
          {
            return 1;
          }

          if (compare_block_hash(message->hash, pending_block->hash))
          {
            if (g_protocol_sync_entry.sync_initiated)
            {
              g_protocol_sync_entry.tx_sync_initiated = 1;
              g_protocol_sync_entry.tx_sync_num_txs = message->num_transactions;
              if (request_sync_next_transaction(net_connection))
              {
                assert(clear_sync_request(0) == 0);
                return 1;
              }

              return 0;
            }
          }
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ:
      {
        get_block_transaction_by_hash_request_t *message = (get_block_transaction_by_hash_request_t*)message_object;
        block_t *block = get_block_from_hash(message->block_hash);
        if (block != NULL)
        {
          transaction_t *transaction = get_tx_by_hash_from_block(block, message->tx_hash);
          if (transaction == NULL)
          {
            free_block(block);
            return 1;
          }

          int32_t tx_index = get_tx_index_from_tx_in_block(block, transaction);
          if (tx_index < 0)
          {
            free_block(block);
            free_transaction(transaction);
            return 1;
          }

          if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP,
            message->block_hash, tx_index, transaction))
          {
            free_block(block);
            free_transaction(transaction);
            return 1;
          }

          free_block(block);
          free_transaction(transaction);
          return 0;
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP:
      {
        get_block_transaction_by_hash_response_t *message = (get_block_transaction_by_hash_response_t*)message_object;
        if (g_protocol_sync_entry.sync_initiated && g_protocol_sync_entry.tx_sync_initiated)
        {
          block_t *pending_block = g_protocol_sync_entry.sync_pending_block;
          if (pending_block == NULL)
          {
            return 1;
          }

          if (compare_block_hash(message->block_hash, pending_block->hash) == 0)
          {
            return 1;
          }

          if (transaction_received(net_connection, message->transaction, message->tx_index))
          {
            return 1;
          }

          return 0;
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ:
      {
        get_block_transaction_by_index_request_t *message = (get_block_transaction_by_index_request_t*)message_object;
        block_t *block = get_block_from_hash(message->block_hash);
        if (block != NULL)
        {
          if (message->tx_index <= block->transaction_count)
          {
            transaction_t *transaction = block->transactions[message->tx_index];
            assert(transaction != NULL);

            if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP,
              message->block_hash, message->tx_index, transaction))
            {
              free_block(block);
              return 1;
            }

            free_block(block);
            return 0;
          }

          free_block(block);
          return 1;
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP:
      {
        get_block_transaction_by_index_response_t *message = (get_block_transaction_by_index_response_t*)message_object;
        if (g_protocol_sync_entry.sync_initiated && g_protocol_sync_entry.tx_sync_initiated)
        {
          block_t *pending_block = g_protocol_sync_entry.sync_pending_block;
          if (pending_block == NULL)
          {
            return 1;
          }

          if (compare_block_hash(message->block_hash, pending_block->hash) == 0)
          {
            return 1;
          }

          if (transaction_received(net_connection, message->transaction, message->tx_index))
          {
            return 1;
          }

          return 0;
        }
      }
      break;
    case PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION:
      {
        incoming_mempool_transaction_t *message = (incoming_mempool_transaction_t*)message_object;
        if (validate_and_add_tx_to_mempool(message->transaction) == 0)
        {
          // relay this incoming mempool transaction to our peers only if we do not already
          // know about the transaction, assuming our peers (or most of them) do not either...
          if (handle_packet_broadcast(PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION, message->transaction))
          {
            return 1;
          }

          return 0;
        }
      }
      break;
    default:
      LOG_DEBUG("Could not handle packet with unknown packet id: %u!", packet_id);
      return 1;
  }

  return 1;
}

int handle_receive_packet(net_connection_t *net_connection, packet_t *packet)
{
  void *message = NULL;
  if (deserialize_message(packet, &message))
  {
    return 1;
  }

  assert(message != NULL);
  if (can_packet_be_processed(net_connection, packet->id) == 0)
  {
    free_message(packet->id, 1, message);
    return 1;
  }

  int result = 0;
  if (net_connection->anonymous)
  {
    result = handle_packet_anonymous(net_connection, packet->id, message);
  }
  else
  {
    result = handle_packet(net_connection, packet->id, message);
  }

  free_message(packet->id, result, message);
  return result;
}

int handle_send_packet(net_connection_t *net_connection, int broadcast, uint32_t packet_id, va_list args)
{
  packet_t *packet = NULL;
  if (serialize_message(&packet, packet_id, args))
  {
    return 1;
  }

  assert(packet != NULL);
  buffer_t *buffer = buffer_init();
  serialize_packet(buffer, packet);
  free_packet(packet);

  uint8_t *data = buffer_get_data(buffer);
  size_t data_len = buffer_get_size(buffer);

  int result = 0;
  if (broadcast)
  {
    result = broadcast_data(net_connection, data, data_len);
  }
  else
  {
    result = send_data(net_connection, data, data_len);
  }

  buffer_free(buffer);
  return result;
}

int handle_packet_sendto(net_connection_t *net_connection, uint32_t packet_id, ...)
{
  assert(net_connection != NULL);
  va_list args;
  va_start(args, packet_id);
  if (handle_send_packet(net_connection, 0, packet_id, args))
  {
    va_end(args);
    return 1;
  }

  va_end(args);
  return 0;
}

int handle_packet_broadcast(uint32_t packet_id, ...)
{
  va_list args;
  va_start(args, packet_id);
  if (handle_send_packet(NULL, 1, packet_id, args))
  {
    va_end(args);
    return 1;
  }

  va_end(args);
  return 0;
}

task_result_t resync_chain(task_t *task, va_list args)
{
  assert(task != NULL);
  if (g_protocol_sync_entry.sync_initiated)
  {
    uint32_t current_time = get_current_time();
    if (current_time - g_protocol_sync_entry.last_sync_ts > RESYNC_BLOCK_REQUEST_DELAY)
    {
      uint32_t last_sync_height = g_protocol_sync_entry.last_sync_height;
      request_sync_block(g_protocol_sync_entry.net_connection, last_sync_height, NULL);
    }
  }

  assert(handle_packet_broadcast(PKT_TYPE_GET_PEERLIST_REQ) == 0);
  assert(handle_packet_broadcast(PKT_TYPE_GET_BLOCK_HEIGHT_REQ) == 0);
  return TASK_RESULT_WAIT;
}
