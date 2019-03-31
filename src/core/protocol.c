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
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#include "common/buffer.h"
#include "common/logger.h"
#include "common/mongoose.h"
#include "common/util.h"

#include "blockchain.h"
#include "mempool.h"
#include "net.h"
#include "p2p.h"
#include "protocol.h"

#include "crypto/cryptoutil.h"

static sync_entry_t g_protocol_sync_entry;

packet_t* make_packet(void)
{
  packet_t *packet = malloc(sizeof(packet_t));
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

int deserialize_packet(packet_t *packet, buffer_t *buffer)
{
  assert(packet != NULL);
  assert(buffer != NULL);

  packet->id = buffer_read_uint32(buffer);
  packet->size = buffer_read_uint32(buffer);
  if (packet->size > 0)
  {
    uint8_t *data = buffer_read_bytes(buffer);
    packet->data = malloc(packet->size);
    memcpy(packet->data, data, packet->size);
    free(data);
  }

  return 0;
}

int free_packet(packet_t *packet)
{
  assert(packet != NULL);
  packet->id = 0;
  packet->size = 0;

  if (packet->data != NULL)
  {
    free(packet->data);
  }

  free(packet);
  return 0;
}

int deserialize_message(packet_t *packet, void **message)
{
  buffer_t *buffer = NULL;
  if (packet->size > 0)
  {
    buffer = buffer_init_data(0, (const uint8_t*)packet->data, packet->size);
  }
  else
  {
    buffer = buffer_init();
  }

  switch (packet->id)
  {
    case PKT_TYPE_CONNECT_REQ:
      {
        uint32_t host_port = buffer_read_uint32(buffer);
        connection_req_t *packed_message = malloc(sizeof(connection_req_t));
        packed_message->host_port = host_port;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_CONNECT_RESP:
      {
        connection_resp_t *packed_message = malloc(sizeof(connection_resp_t));
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_PEERLIST_REQ:
      {
        get_peerlist_req_t *packed_message = malloc(sizeof(get_peerlist_req_t));
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_PEERLIST_RESP:
      {
        uint32_t peerlist_data_size = buffer_read_uint32(buffer);
        uint8_t *peerlist_data = buffer_read_bytes(buffer);
        get_peerlist_resp_t *packed_message = malloc(sizeof(get_peerlist_resp_t));
        packed_message->peerlist_data_size = peerlist_data_size;
        packed_message->peerlist_data = peerlist_data;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_INCOMING_BLOCK:
      {
        block_t *block = deserialize_block(buffer);
        assert(block != NULL);

        incoming_block_t *packed_message = malloc(sizeof(incoming_block_t));
        packed_message->block = block;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION:
      {
        transaction_t *transaction = deserialize_transaction(buffer);
        assert(transaction != NULL);

        incoming_mempool_transaction_t *packed_message = malloc(sizeof(incoming_mempool_transaction_t));
        packed_message->transaction = transaction;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {
        get_block_height_request_t *packed_message = malloc(sizeof(get_block_height_request_t));
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      {
        uint32_t height = buffer_read_uint32(buffer);
        uint8_t *hash = buffer_read_bytes(buffer);
        assert(hash != NULL);

        get_block_height_response_t *packed_message = malloc(sizeof(get_block_height_response_t));
        packed_message->height = height;
        packed_message->hash = hash;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_REQ:
      {
        uint8_t *hash = buffer_read_bytes(buffer);
        get_block_by_hash_request_t *packed_message = malloc(sizeof(get_block_by_hash_request_t));
        packed_message->hash = hash;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_RESP:
      {
        uint32_t height = buffer_read_uint32(buffer);
        block_t *block = deserialize_block(buffer);
        assert(block != NULL);

        get_block_by_hash_response_t *packed_message = malloc(sizeof(get_block_by_hash_response_t));
        packed_message->height = height;
        packed_message->block = block;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_REQ:
      {
        uint32_t height = buffer_read_uint32(buffer);
        get_block_by_height_request_t *packed_message = malloc(sizeof(get_block_by_height_request_t));
        packed_message->height = height;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP:
      {
        uint8_t *hash = buffer_read_bytes(buffer);
        block_t *block = deserialize_block(buffer);
        assert(block != NULL);

        get_block_by_height_response_t *packed_message = malloc(sizeof(get_block_by_height_response_t));
        packed_message->hash = hash;
        packed_message->block = block;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ:
      {
        uint8_t *hash = buffer_read_bytes(buffer);
        get_block_num_transactions_request_t *packed_message = malloc(sizeof(get_block_num_transactions_request_t));
        packed_message->hash = hash;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP:
      {
        uint8_t *hash = buffer_read_bytes(buffer);
        uint64_t num_transactions = buffer_read_uint64(buffer);
        get_block_num_transactions_response_t *packed_message = malloc(sizeof(get_block_num_transactions_response_t));
        packed_message->hash = hash;
        packed_message->num_transactions = num_transactions;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ:
      {

      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP:
      {

      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ:
      {
        uint8_t *block_hash = buffer_read_bytes(buffer);
        uint32_t tx_index = buffer_read_uint32(buffer);
        get_block_transaction_by_index_request_t *packed_message = malloc(sizeof(get_block_transaction_by_index_request_t));
        packed_message->block_hash = block_hash;
        packed_message->tx_index = tx_index;
        *message = packed_message;
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP:
      {
        uint8_t *block_hash = buffer_read_bytes(buffer);
        uint32_t tx_index = buffer_read_uint32(buffer);
        transaction_t *transaction = deserialize_transaction(buffer);
        assert(transaction != NULL);

        get_block_transaction_by_index_response_t *packed_message = malloc(sizeof(get_block_transaction_by_index_response_t));
        packed_message->block_hash = block_hash;
        packed_message->tx_index = tx_index;
        packed_message->transaction = transaction;
        *message = packed_message;
      }
      break;
    default:
      LOG_DEBUG("Could not deserialize packet with unknown packet id: %u!", packet->id);
      buffer_free(buffer);
      return 1;
  }

  buffer_free(buffer);
  return 0;
}

int serialize_message(packet_t **packet, uint32_t packet_id, va_list args)
{
  buffer_t *buffer = buffer_init();
  switch (packet_id)
  {
    case PKT_TYPE_CONNECT_REQ:
      {
        uint32_t host_port = va_arg(args, uint32_t);
        buffer_write_uint32(buffer, host_port);
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
        buffer_write_uint32(buffer, peerlist_data_size);
        buffer_write_bytes(buffer, (uint8_t*)buffer_get_data(peerlist_buffer), peerlist_data_size);
      }
      break;
    case PKT_TYPE_INCOMING_BLOCK:
      {
        block_t *block = va_arg(args, block_t*);
        assert(block != NULL);

        serialize_block(buffer, block);
      }
      break;
    case PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION:
      {
        transaction_t *transaction = va_arg(args, transaction_t*);
        assert(transaction != NULL);

        serialize_transaction(buffer, transaction);
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

      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP:
      {

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
    default:
      LOG_DEBUG("Could not serialize packet with unknown packet id: %u!", packet_id);
      return 1;
  }

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  packet_t *serialized_packet = make_packet();
  serialized_packet->id = packet_id;
  serialized_packet->size = data_len;
  if (data_len > 0)
  {
    serialized_packet->data = malloc(data_len);
    memcpy(serialized_packet->data, data, data_len);
  }

  *packet = serialized_packet;
  buffer_free(buffer);
  return 0;
}

void free_message(uint32_t packet_id, void *message_object)
{
  switch (packet_id)
  {
    case PKT_TYPE_CONNECT_REQ:
      {
        connection_req_t *message = (connection_req_t*)message_object;
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
    case PKT_TYPE_INCOMING_BLOCK:
      {
        incoming_block_t *message = (incoming_block_t*)message_object;
        free_block(message->block);
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

      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP:
      {

      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ:
      {

      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP:
      {

      }
      break;
    default:
      LOG_DEBUG("Could not free packet with unknown packet id: %u!", packet_id);
      break;
  }
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
  g_protocol_sync_entry.sync_pending_block = NULL;
  g_protocol_sync_entry.sync_height = 0;
  g_protocol_sync_entry.sync_start_height = -1;

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

int clear_tx_sync_request(void)
{
  if (g_protocol_sync_entry.sync_initiated == 0 || g_protocol_sync_entry.tx_sync_initiated == 0)
  {
    return 1;
  }

  g_protocol_sync_entry.sync_pending_block = NULL;

  g_protocol_sync_entry.tx_sync_initiated = 0;
  g_protocol_sync_entry.tx_sync_num_txs = 0;
  g_protocol_sync_entry.last_tx_sync_index = -1;
  g_protocol_sync_entry.last_tx_sync_ts = 0;
  g_protocol_sync_entry.last_tx_sync_tries = 0;
  return 0;
}

int check_sync_status(void)
{
  uint32_t current_block_height = get_block_height();
  if (current_block_height >= g_protocol_sync_entry.sync_height)
  {
    if (clear_sync_request(1) == 0)
    {
      LOG_INFO("Successfully synced blockchain at block height: %u", current_block_height);
      return 0;
    }
    else
    {
      return 1;
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
    if (clear_sync_request(0))
    {
      LOG_WARNING("Timed out when requesting block at height: %u!", sync_height);
    }

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
  uint32_t block_height = g_protocol_sync_entry.last_sync_height;
  if (has_block_by_height(block_height) == 0)
  {
    LOG_ERROR("Cannot request next block when previous block at height: %u, was not found in the blockchain!", block_height);
    return 1;
  }

  uint32_t sync_height = g_protocol_sync_entry.last_sync_height + 1;
  return request_sync_block(net_connection, sync_height, NULL);
}

int request_sync_previous_block(net_connection_t *net_connection)
{
  uint32_t sync_height = g_protocol_sync_entry.last_sync_height - 1;
  return request_sync_block(net_connection, sync_height, NULL);
}

int request_sync_transaction(net_connection_t *net_connection, uint8_t *block_hash, uint32_t tx_index, uint8_t *tx_hash)
{
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
  block_t *pending_block = g_protocol_sync_entry.sync_pending_block;
  assert(pending_block != NULL);

  uint32_t tx_sync_index = g_protocol_sync_entry.last_tx_sync_index + 1;
  if (tx_sync_index > pending_block->transaction_count)
  {
    return 1;
  }

  return request_sync_transaction(net_connection, pending_block->hash, tx_sync_index, NULL);
}

int block_header_received(net_connection_t *net_connection, block_t *block)
{
  assert(block != NULL);

  // validate the block's hash before attempting to establish a sync request
  // at that block's height in the blockchain...
  if (valid_block_hash(block) == 0)
  {
    assert(clear_sync_request(0) == 0);
    return 1;
  }

  if (g_protocol_sync_entry.sync_initiated)
  {
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
        LOG_INFO("Found sync starting block at height: %u!", g_protocol_sync_entry.last_sync_height);
        g_protocol_sync_entry.sync_start_height = g_protocol_sync_entry.last_sync_height;
        can_rollback_and_resync = 1;
      }
      else if (g_protocol_sync_entry.last_sync_height <= 0)
      {
        LOG_WARNING("Unable to find sync starting height, continuing anyway...");
        g_protocol_sync_entry.sync_start_height = 0;
        can_rollback_and_resync = 1;
      }
      else
      {
        if (request_sync_previous_block(net_connection))
        {
          return 1;
        }
      }

      if (can_rollback_and_resync)
      {
        g_protocol_sync_entry.sync_finding_top_block = 0;
        if (rollback_blockchain_and_resync())
        {
          // if by some way we fail to rollback and resync and we
          // fail to clear our sync request, then throw an assertion,
          // this should never happen...
          assert(clear_sync_request(0) == 0);
        }
      }
    }
    else if (g_protocol_sync_entry.tx_sync_initiated == 0)
    {
      block->transaction_count = 0;
      block->transactions = NULL;
      g_protocol_sync_entry.sync_pending_block = block;
      if (handle_packet_sendto(net_connection, PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ, block->hash))
      {
        free_block(block);
        g_protocol_sync_entry.sync_pending_block = NULL;

        // we failed to request transactions for this block header,
        // clear the sync request in attempt to resync this block later...
        assert(clear_sync_request(0) == 0);
        return 1;
      }
    }
  }

  return 0;
}

int block_header_sync_complete(net_connection_t *net_connection, block_t *block)
{
  assert(block != NULL);
  if (validate_and_insert_block(block))
  {
    LOG_INFO("Received block at height: %u", g_protocol_sync_entry.last_sync_height);
    if (check_sync_status())
    {
      if (request_sync_next_block(g_protocol_sync_entry.net_connection))
      {
        return 1;
      }
    }
  }

  // if any of this block's transactions are still in our memory pool,
  // remove them since they have been "set in stone" within the block...
  for (int i = 0; i < block->transaction_count; i++)
  {
    transaction_t *tx = block->transactions[i];
    assert(tx != NULL);

    if (is_tx_in_mempool(tx))
    {
      assert(remove_tx_from_mempool(tx) == 0);
    }
  }

  return 0;
}

int rollback_blockchain_and_resync(void)
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

  if (request_sync_next_block(g_protocol_sync_entry.net_connection))
  {
    return 1;
  }

  return 0;
}

int handle_packet_anonymous(net_connection_t *net_connection, uint32_t packet_id, void *message_object)
{
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

        peer_t *peer = init_peer(peer_id, net_connection);
        assert(add_peer(peer) == 0);

        if (handle_packet_sendto(net_connection, PKT_TYPE_CONNECT_RESP))
        {
          free_peer(peer);
          return 1;
        }
      }
      break;
    case PKT_TYPE_CONNECT_RESP:
      {
        connection_resp_t *message = (connection_resp_t*)message_object;
        net_connection->anonymous = 0;
      }
      break;
    default:
      assert(close_net_connection(net_connection) == 0);
      return 1;
  }

  return 0;
}

int handle_packet(net_connection_t *net_connection, uint32_t packet_id, void *message_object)
{
  switch (packet_id)
  {
    case PKT_TYPE_GET_PEERLIST_REQ:
      {
        get_peerlist_req_t *message = (get_peerlist_req_t*)message_object;
        uint16_t num_peers = get_num_peers();

        buffer_t *buffer = buffer_init();
        buffer_write_uint16(buffer, num_peers);

        for (int i = 0; i < num_peers; i++)
        {
          peer_t *peer = get_peer_from_index(i);
          assert(peer != NULL);

          net_connection_t *peer_net_connection = peer->net_connection;
          assert(peer_net_connection != NULL);

          struct mg_connection *peer_connection = peer_net_connection->connection;
          assert(peer_connection != NULL);

          uint32_t remote_ip = ntohl(*(uint32_t*)&peer_connection->sa.sin.sin_addr);
          buffer_write_uint32(buffer, remote_ip);
          buffer_write_uint16(buffer, peer_net_connection->host_port);
        }

        if (handle_packet_sendto(net_connection, PKT_TYPE_GET_PEERLIST_RESP, buffer))
        {
          buffer_free(buffer);
          return 1;
        }

        buffer_free(buffer);
      }
      break;
    case PKT_TYPE_GET_PEERLIST_RESP:
      {
        get_peerlist_resp_t *message = (get_peerlist_resp_t*)message_object;
        buffer_t *buffer = buffer_init_data(0, message->peerlist_data, message->peerlist_data_size);
        uint32_t num_peers = buffer_read_uint16(buffer);
        for (int i = 0; i < num_peers; i++)
        {
          uint32_t remote_ip = buffer_read_uint32(buffer);
          uint16_t host_port = buffer_read_uint16(buffer);
          if (remote_ip == convert_str_to_ip(get_net_host_address()) && host_port == get_net_host_port())
          {
            continue;
          }
          else
          {
            if (is_local_address(remote_ip) && host_port == get_net_host_port())
            {
              continue;
            }
          }

          uint64_t peer_id = concatenate(remote_ip, host_port);
          if (has_peer(peer_id))
          {
            continue;
          }

          if (get_num_peers() >= MAX_P2P_PEERS_COUNT)
          {
            break;
          }

          const char *bind_address = convert_ip_to_str(remote_ip);
          if (connect_net_to_peer(bind_address, host_port))
          {
            return 1;
          }
        }
      }
      break;
    case PKT_TYPE_INCOMING_BLOCK:
      {
        /*incoming_block_t *message = (incoming_block_t*)message_object;
        if (validate_and_insert_block_nolock(message->block))
        {
          LOG_INFO("Added incoming block at height: %u.", get_block_height());
        }*/
      }
      break;
    case PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION:
      {
        incoming_mempool_transaction_t *message = (incoming_mempool_transaction_t*)message_object;
        if (add_tx_to_mempool(message->transaction) == 0)
        {
          // relay this incoming mempool transaction to our peers only if we do not already
          // know about the transaction, assuming our peers (or most of them) do not either...
          if (handle_packet_broadcast(PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION, message->transaction))
          {
            return 1;
          }
        }
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
            LOG_INFO("Found potential alternative blockchain at height: %u.", message->height);
            clear_sync_request(0);

            if (init_sync_request(message->height, net_connection) == 0)
            {
              if (current_block_height > 0)
              {
                LOG_INFO("Determining best synchronization starting height...");
                g_protocol_sync_entry.last_sync_height = current_block_height + 1;
                if (request_sync_previous_block(net_connection))
                {
                  return 1;
                }
              }
              else
              {
                g_protocol_sync_entry.sync_start_height = 0;
                LOG_INFO("Beginning sync with presumed top block: %u...", message->height);
                if (request_sync_next_block(net_connection))
                {
                  LOG_ERROR("Failed to request next block!");
                  return 1;
                }
              }
            }
          }
        }
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
              return 1;
            }
          }

          free_block(block);
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HASH_RESP:
      {
        get_block_by_hash_response_t *message = (get_block_by_hash_response_t*)message_object;
        if (block_header_received(net_connection, message->block))
        {
          return 1;
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
              return 1;
            }

            free_block(block);
          }
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP:
      {
        get_block_by_height_response_t *message = (get_block_by_height_response_t*)message_object;
        if (block_header_received(net_connection, message->block))
        {
          return 1;
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
            return 1;
          }

          free_block(block);
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP:
      {
        get_block_num_transactions_response_t *message = (get_block_num_transactions_response_t*)message_object;
        if (g_protocol_sync_entry.sync_initiated && g_protocol_sync_entry.sync_pending_block != NULL
          && g_protocol_sync_entry.tx_sync_initiated == 0)
        {
          block_t *block = g_protocol_sync_entry.sync_pending_block;
          assert(block != NULL);

          if (compare_block_hash(message->hash, block->hash))
          {
            if (g_protocol_sync_entry.sync_initiated)
            {
              g_protocol_sync_entry.tx_sync_initiated = 1;
              g_protocol_sync_entry.tx_sync_num_txs = message->num_transactions;
              if (request_sync_next_transaction(net_connection))
              {
                return 1;
              }
            }
          }
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ:
      {

      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP:
      {

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
              block->hash, message->tx_index, transaction))
            {
              return 1;
            }
          }
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP:
      {
        get_block_transaction_by_index_response_t *message = (get_block_transaction_by_index_response_t*)message_object;
        if (g_protocol_sync_entry.sync_initiated && g_protocol_sync_entry.tx_sync_initiated)
        {
          block_t *block = g_protocol_sync_entry.sync_pending_block;
          assert(block != NULL);

          transaction_t *transaction = message->transaction;
          assert(transaction != NULL);

          assert(add_transaction_to_block(block, transaction, message->tx_index) == 0);
          if (message->tx_index + 1 < g_protocol_sync_entry.tx_sync_num_txs)
          {
            if (request_sync_next_transaction(net_connection))
            {
              return 1;
            }
          }
          else
          {
            // compute the block's merkle root again and compare it against
            // the block's currently defined merkle root to see if
            // this block does infact have the correct transactions it requires...
            if (valid_merkle_root(block))
            {
              // must clear the tx sync entry cache before calling block_header_sync_complete,
              // otherwise the entire sync entry cache will be cleared and this assertion will fail...
              assert(clear_tx_sync_request() == 0);
              if (block_header_sync_complete(net_connection, block))
              {
                return 1;
              }
            }
            else
            {
              assert(clear_sync_request(0) == 0);
            }
          }
        }
      }
      break;
    default:
      LOG_DEBUG("Could not handle packet with unknown packet id: %u!", packet_id);
      return 1;
  }

  return 0;
}

int handle_receive_packet(net_connection_t *net_connection, packet_t *packet)
{
  void *message = NULL;
  if (deserialize_message(packet, &message) || message == NULL)
  {
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

  free_message(packet->id, message);
  return result;
}

int handle_send_packet(net_connection_t *net_connection, int broadcast, uint32_t packet_id, va_list args)
{
  packet_t *packet = NULL;
  if (serialize_message(&packet, packet_id, args) || packet == NULL)
  {
    return 1;
  }

  buffer_t *buffer = buffer_init();
  serialize_packet(buffer, packet);
  free_packet(packet);

  const uint8_t *data = buffer_get_data(buffer);
  size_t data_len = buffer_get_size(buffer);

  uint8_t raw_data[data_len];
  memcpy(&raw_data, data, data_len);
  buffer_free(buffer);

  int result = 0;
  if (broadcast)
  {
    result = broadcast_data(net_connection, (uint8_t*)&raw_data, data_len);
  }
  else
  {
    result = send_data(net_connection, (uint8_t*)&raw_data, data_len);
  }

  return result;
}

int handle_packet_sendto(net_connection_t *net_connection, uint32_t packet_id, ...)
{
  va_list args;
  va_start(args, packet_id);
  if (handle_send_packet(net_connection, 0, packet_id, args))
  {
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
    return 1;
  }

  va_end(args);
  return 0;
}

task_result_t resync_chain(task_t *task, va_list args)
{
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
