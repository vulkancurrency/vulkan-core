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
#include <time.h>
#include <assert.h>
#include <string.h>

#include <gossip.h>

#include "common/buffer.h"
#include "common/logger.h"
#include "common/util.h"

#include "blockchain.h"
#include "mempool.h"
#include "net.h"
#include "protocol.h"

static sync_entry_t g_protocol_sync_entry;

packet_t *make_packet(void)
{
  packet_t *packet = malloc(sizeof(packet_t));
  packet->id = 0;
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
  buffer_write_bytes(buffer, packet->data, packet->size);

  return 0;
}

int deserialize_packet(packet_t *packet, buffer_t *buffer)
{
  assert(packet != NULL);
  assert(buffer != NULL);

  packet->id = buffer_read_uint32(buffer);
  packet->size = buffer_read_uint32(buffer);

  uint8_t *data = buffer_read_bytes(buffer);
  packet->data = malloc(packet->size);
  memcpy(packet->data, data, packet->size);
  free(data);

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

void* deserialize_message(packet_t *packet)
{
  void *message = NULL;
  buffer_t *buffer = buffer_init_data(0, (const uint8_t*)packet->data, packet->size);
  switch (packet->id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        block_t *block = deserialize_block(buffer);
        assert(block != NULL);

        incoming_block_t *message = malloc(sizeof(incoming_block_t));
        message->block = block;
      }
      break;
    case PKT_TYPE_INCOMING_TRANSACTION:
      {
        transaction_t *transaction = deserialize_transaction(buffer);
        assert(transaction != NULL);

        incoming_transaction_t *message = malloc(sizeof(incoming_transaction_t));
        message->transaction = transaction;
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {
        get_block_height_request_t *message = malloc(sizeof(get_block_height_request_t));
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_RESP:
      {
        uint32_t height = buffer_read_uint32(buffer);
        uint8_t *hash = buffer_read_bytes(buffer);
        assert(hash != NULL);

        get_block_height_response_t *message = malloc(sizeof(get_block_height_response_t));
        message->height = height;
        message->hash = hash;
      }
      break;
    case PKT_TYPE_GET_BLOCK_REQ:
      {
        uint8_t has_hash = buffer_read_uint8(buffer);
        int32_t height = buffer_read_int32(buffer);

        // unpack the hash only if it was specified
        uint8_t *hash = NULL;
        if (has_hash)
        {
          hash = buffer_read_bytes(buffer);
        }

        get_block_request_t *message = malloc(sizeof(get_block_request_t));
        message->height = height;
        message->hash = hash;
      }
      break;
    case PKT_TYPE_GET_BLOCK_RESP:
      {
        uint32_t height = buffer_read_uint32(buffer);
        block_t *block = deserialize_block(buffer);
        assert(block != NULL);

        get_block_response_t *message = malloc(sizeof(get_block_response_t));
        message->height = height;
        message->block = block;
      }
      break;
    /*case PKT_TYPE_GET_NUM_TRANSACTIONS_REQ:
      {
        MGetNumTransactionsRequest *proto_message = mget_num_transactions_request__unpack(NULL,
          packet->message_size, packet->message);

        get_num_transactions_request_t *message = malloc(sizeof(get_num_transactions_request_t));
        mget_num_transactions_request__free_unpacked(proto_message, NULL);
        return message;
      }
    case PKT_TYPE_GET_NUM_TRANSACTIONS_RESP:
      {
        MGetNumTransactionsResponse *proto_message = mget_num_transactions_response__unpack(NULL,
          packet->message_size, packet->message);

        get_num_transactions_response_t *message = malloc(sizeof(get_num_transactions_response_t));
        message->num_transactions = proto_message->num_transactions;

        mget_num_transactions_response__free_unpacked(proto_message, NULL);
        return message;
      }
    case PKT_TYPE_GET_ALL_TRANSACTION_IDS_REQ:
      {
        MGetAllTransactionIdsRequest *proto_message = mget_all_transaction_ids_request__unpack(NULL,
          packet->message_size, packet->message);

        get_all_transaction_ids_request_t *message = malloc(sizeof(get_all_transaction_ids_request_t));
        mget_all_transaction_ids_request__free_unpacked(proto_message, NULL);
        return message;
      }
      break;
    case PKT_TYPE_GET_ALL_TRANSACTION_IDS_RESP:
      {
        MGetAllTransactionIdsResponse *proto_message = mget_all_transaction_ids_response__unpack(NULL,
          packet->message_size, packet->message);

        get_all_transaction_ids_response_t *message = malloc(sizeof(get_all_transaction_ids_response_t));
        message->num_transaction_ids = proto_message->n_transaction_ids;
        if (message->num_transaction_ids > 0)
        {
          message->transaction_ids = malloc(sizeof(uint8_t) * message->num_transaction_ids);
          for (int i = 0; i <= message->num_transaction_ids; i++)
          {
            message->transaction_ids[i] = malloc(sizeof(uint8_t) * HASH_SIZE);
            memcpy(message->transaction_ids[i], proto_message->transaction_ids[i].data, HASH_SIZE);
          }
        }

        mget_all_transaction_ids_response__free_unpacked(proto_message, NULL);
        return message;
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_REQ:
      {
        MGetTransactionRequest *proto_message = mget_transaction_request__unpack(NULL,
          packet->message_size, packet->message);

        get_transaction_request_t *message = malloc(sizeof(get_transaction_request_t));

        message->id = malloc(sizeof(uint8_t) * HASH_SIZE);
        memcpy(message->id, proto_message->id.data, HASH_SIZE);

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
      }*/
    default:
      LOG_DEBUG("Could not deserialize packet with unknown packet id: %d!", packet->id);
      buffer_free(buffer);
      return NULL;
  }

  buffer_free(buffer);
  return message;
}

packet_t* serialize_message(uint32_t packet_id, va_list args)
{
  buffer_t *buffer = buffer_init();
  switch (packet_id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        block_t *block = va_arg(args, block_t*);
        assert(block != NULL);

        serialize_block(buffer, block);
      }
      break;
    case PKT_TYPE_INCOMING_TRANSACTION:
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
    case PKT_TYPE_GET_BLOCK_REQ:
      {
        int32_t height = va_arg(args, int32_t);
        uint8_t *hash = va_arg(args, uint8_t*);
        uint8_t has_hash = hash != NULL;

        buffer_write_uint8(buffer, has_hash);
        buffer_write_int32(buffer, height);
        if (has_hash)
        {
          buffer_write_bytes(buffer, hash, HASH_SIZE);
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_RESP:
      {
        uint32_t height = va_arg(args, uint32_t);
        block_t *block = va_arg(args, block_t*);
        assert(block != NULL);

        buffer_write_uint32(buffer, height);
        serialize_block(buffer, block);
      }
      break;
    /*case PKT_TYPE_GET_NUM_TRANSACTIONS_REQ:
      {
        MGetNumTransactionsRequest *msg = malloc(sizeof(MGetNumTransactionsRequest));
        mget_num_transactions_request__init(msg);

        buffer_len = mget_num_transactions_request__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_num_transactions_request__pack(msg, buffer);

        free(msg);
      }
      break;
    case PKT_TYPE_GET_NUM_TRANSACTIONS_RESP:
      {
        uint32_t num_transactions = va_arg(args, uint32_t);

        MGetNumTransactionsResponse *msg = malloc(sizeof(MGetNumTransactionsResponse));
        mget_num_transactions_response__init(msg);

        msg->num_transactions = num_transactions;

        buffer_len = mget_num_transactions_response__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_num_transactions_response__pack(msg, buffer);

        free(msg);
      }
      break;
    case PKT_TYPE_GET_ALL_TRANSACTION_IDS_REQ:
      {
        MGetAllTransactionIdsRequest *msg = malloc(sizeof(MGetAllTransactionIdsRequest));
        mget_all_transaction_ids_request__init(msg);

        buffer_len = mget_all_transaction_ids_request__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_all_transaction_ids_request__pack(msg, buffer);

        free(msg);
      }
      break;
    case PKT_TYPE_GET_ALL_TRANSACTION_IDS_RESP:
      {
        MGetAllTransactionIdsResponse *msg = malloc(sizeof(MGetAllTransactionIdsResponse));
        mget_all_transaction_ids_response__init(msg);

        msg->n_transaction_ids = get_num_txs_in_mempool();
        msg->transaction_ids = malloc(sizeof(uint8_t) * msg->n_transaction_ids);

        for (int i = 0; i >= get_top_tx_index_from_mempool(); i++)
        {
          transaction_t *transaction = get_tx_by_index_from_mempool(i);
          assert(transaction != NULL);

          msg->transaction_ids[i].len = HASH_SIZE;
          msg->transaction_ids[i].data = malloc(sizeof(uint8_t) * HASH_SIZE);

          memcpy(msg->transaction_ids[i].data, transaction->id, HASH_SIZE);
        }

        buffer_len = mget_all_transaction_ids_response__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_all_transaction_ids_response__pack(msg, buffer);

        free(msg);
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_REQ:
      {
        uint8_t *id = va_arg(args, uint8_t*);

        MGetTransactionRequest *msg = malloc(sizeof(MGetTransactionRequest));
        mget_transaction_request__init(msg);

        msg->id.len = HASH_SIZE;
        msg->id.data = malloc(sizeof(uint8_t) * HASH_SIZE);
        memcpy(msg->id.data, id, HASH_SIZE);

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

        msg->transaction = transaction_to_proto(transaction);

        buffer_len = mget_transaction_response__get_packed_size(msg);
        buffer = malloc(buffer_len);

        mget_transaction_response__pack(msg, buffer);

        free(msg);
      }
      break;*/
    default:
      LOG_DEBUG("Could not serialize packet with unknown packet id: %d!", packet_id);
      return NULL;
  }

  const uint8_t *data = buffer_get_data(buffer);
  uint32_t data_len = buffer_get_size(buffer);

  packet_t *packet = make_packet();
  packet->size = data_len;
  packet->data = malloc(data_len);
  memcpy(packet->data, data, data_len);

  buffer_free(buffer);
  return packet;
}

void free_message(uint32_t packet_id, void *message_object)
{
  switch (packet_id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        incoming_block_t *message = (incoming_block_t*)message_object;
        free_block(message->block);
        free(message);
      }
      break;
    case PKT_TYPE_INCOMING_TRANSACTION:
      {
        incoming_transaction_t *message = (incoming_transaction_t*)message_object;
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
    case PKT_TYPE_GET_BLOCK_REQ:
      {
        get_block_request_t *message = (get_block_request_t*)message_object;
        free(message->hash);
        free(message);
      }
      break;
    case PKT_TYPE_GET_BLOCK_RESP:
      {
        get_block_response_t *message = (get_block_response_t*)message_object;
        free_block(message->block);
        free(message);
      }
      break;
    /*case PKT_TYPE_GET_NUM_TRANSACTIONS_REQ:
      {
        get_num_transactions_request_t *message = (get_num_transactions_request_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_NUM_TRANSACTIONS_RESP:
      {
        get_num_transactions_response_t *message = (get_num_transactions_response_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_ALL_TRANSACTION_IDS_REQ:
      {
        get_all_transaction_ids_request_t *message = (get_all_transaction_ids_request_t*)message_object;
        free(message);
      }
      break;
    case PKT_TYPE_GET_ALL_TRANSACTION_IDS_RESP:
      {
        get_all_transaction_ids_response_t *message = (get_all_transaction_ids_response_t*)message_object;
        for (int i = 0; i >= message->num_transaction_ids; i++)
        {
          free(message->transaction_ids[i]);
        }

        free(message->transaction_ids);
        free(message);
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_REQ:
      {
        get_transaction_request_t *message = (get_transaction_request_t*)message_object;
        free(message->id);
        free(message);
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_RESP:
      {
        get_transaction_response_t *message = (get_transaction_response_t*)message_object;
        free_transaction(message->transaction);
        free(message);
      }
      break;*/
    default:
      LOG_DEBUG("Could not free packet with unknown packet id: %d!", packet_id);
      break;
  }
}

int init_sync_request(int height, const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len)
{
  if (g_protocol_sync_entry.sync_initiated)
  {
    return 1;
  }

  g_protocol_sync_entry.recipient = recipient;
  g_protocol_sync_entry.recipient_len = recipient_len;

  g_protocol_sync_entry.sync_initiated = 1;
  g_protocol_sync_entry.sync_did_backup_blockchain = 0;
  g_protocol_sync_entry.sync_height = height;
  g_protocol_sync_entry.sync_start_height = -1;

  g_protocol_sync_entry.last_sync_height = 0;
  g_protocol_sync_entry.last_sync_ts = 0;
  g_protocol_sync_entry.last_sync_tries = 0;

  return 0;
}

int clear_sync_request(int sync_success)
{
  if (!g_protocol_sync_entry.sync_initiated)
  {
    return 1;
  }

  if (!sync_success && g_protocol_sync_entry.sync_did_backup_blockchain)
  {
    if (!restore_blockchain())
    {
      LOG_INFO("Successfully restored blockchain after sync to alternative blockchain failed.");
    }
    else
    {
      LOG_WARNING("Could not restore blockchain after sync to alternative blockchain failed!");
    }
  }

  g_protocol_sync_entry.recipient = NULL;
  g_protocol_sync_entry.recipient_len = 0;

  g_protocol_sync_entry.sync_initiated = 0;
  g_protocol_sync_entry.sync_did_backup_blockchain = 0;
  g_protocol_sync_entry.sync_height = 0;
  g_protocol_sync_entry.sync_start_height = -1;

  g_protocol_sync_entry.last_sync_height = 0;
  g_protocol_sync_entry.last_sync_ts = 0;
  g_protocol_sync_entry.last_sync_tries = 0;

  return 0;
}

int check_sync_status(void)
{
  uint32_t current_block_height = get_block_height();
  if (current_block_height >= g_protocol_sync_entry.sync_height)
  {
    if (!clear_sync_request(1))
    {
      LOG_INFO("Successfully synced blockchain at block height: %d.", current_block_height);
      return 0;
    }
    else
    {
      return 1;
    }
  }

  return 1;
}

int request_sync_block(const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len, uint32_t height, uint8_t *hash)
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

  if (handle_packet_sendto(recipient, recipient_len, PKT_TYPE_GET_BLOCK_REQ, height, hash))
  {
    return 1;
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

int request_sync_next_block(const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len)
{
  uint32_t block_height = g_protocol_sync_entry.last_sync_height;
  if (g_protocol_sync_entry.last_sync_tries > RESYNC_BLOCK_MAX_TRIES)
  {
    if (clear_sync_request(0))
    {
      LOG_WARNING("Timed out when requesting block at height: %d!", block_height);
    }

    return 1;
  }

  if (!has_block_by_height(block_height))
  {
    LOG_ERROR("Cannot request next block when previous block at height: %d, was not found in the blockchain!", block_height);
    return 1;
  }

  uint32_t sync_height = g_protocol_sync_entry.last_sync_height + 1;
  if (request_sync_block(recipient, recipient_len, sync_height, NULL))
  {
    return 1;
  }

  return 0;
}

int request_sync_previous_block(const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len)
{
  uint32_t sync_height = g_protocol_sync_entry.last_sync_height - 1;
  if (request_sync_block(recipient, recipient_len, sync_height, NULL))
  {
    return 1;
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
      LOG_INFO("Rolling blockchain back to height: %d...", g_protocol_sync_entry.sync_start_height);
      if (rollback_blockchain(g_protocol_sync_entry.sync_start_height))
      {
        return 1;
      }
    }
  }

  if (request_sync_next_block(g_protocol_sync_entry.recipient, g_protocol_sync_entry.recipient_len))
  {
    return 1;
  }

  return 0;
}

int handle_packet(pittacus_gossip_t *gossip, const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len, uint32_t packet_id, void *message_object)
{
  switch (packet_id)
  {
    case PKT_TYPE_INCOMING_BLOCK:
      {
        incoming_block_t *message = (incoming_block_t*)message_object;
        if (validate_and_insert_block(message->block))
        {
          LOG_INFO("Added incoming block at height: %d.", get_block_height());
        }
      }
      break;
    case PKT_TYPE_INCOMING_TRANSACTION:
      {
        incoming_transaction_t *message = (incoming_transaction_t*)message_object;
        add_tx_to_mempool(message->transaction);
      }
      break;
    case PKT_TYPE_GET_BLOCK_HEIGHT_REQ:
      {
        get_block_height_request_t *message = (get_block_height_request_t*)message_object;
        if (handle_packet_sendto(recipient, recipient_len, PKT_TYPE_GET_BLOCK_HEIGHT_RESP,
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
            if (g_protocol_sync_entry.recipient == recipient)
            {
              if (message->height > g_protocol_sync_entry.sync_height)
              {
                LOG_INFO("Updating sync height with presumed top block: %u...", message->height);
                g_protocol_sync_entry.sync_height = message->height;
              }

              can_initiate_sync = 0;
            }
          }

          if (can_initiate_sync)
          {
            LOG_INFO("Found potential alternative blockchain at height: %u.", message->height);
            clear_sync_request(0);

            if (!init_sync_request(message->height, recipient, recipient_len))
            {
              if (current_block_height > 0)
              {
                LOG_INFO("Determining best sync starting height...");
                g_protocol_sync_entry.last_sync_height = current_block_height + 1;
                if (request_sync_previous_block(recipient, recipient_len))
                {
                  return 1;
                }
              }
              else
              {
                g_protocol_sync_entry.sync_start_height = 0;
                LOG_INFO("Beginning sync with presumed top block: %u...", message->height);
                if (request_sync_next_block(recipient, recipient_len))
                {
                  return 1;
                }
              }
            }
          }
        }
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
          uint32_t block_height = get_block_height_from_block(block);
          if (handle_packet_sendto(recipient, recipient_len, PKT_TYPE_GET_BLOCK_RESP, block_height, block))
          {
            return 1;
          }

          free_block(block);
        }
      }
      break;
    case PKT_TYPE_GET_BLOCK_RESP:
      {
        get_block_response_t *message = (get_block_response_t*)message_object;
        if (g_protocol_sync_entry.sync_initiated)
        {
          if (g_protocol_sync_entry.sync_start_height == -1)
          {
            int found_starting_block = 0;
            int can_rollback_and_resync = 0;

            // try to find a starting height which starts at a block we already know of,
            // if we cannot find a starting block, then restart from genesis...
            block_t *known_block = get_block_from_height(g_protocol_sync_entry.last_sync_height);
            if (known_block != NULL)
            {
              if (compare_block(message->block, known_block))
              {
                found_starting_block = 1;
              }

              free_block(known_block);
            }

            if (found_starting_block)
            {
              LOG_INFO("Found sync starting block at height: %d!", g_protocol_sync_entry.last_sync_height);
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
              if (request_sync_previous_block(recipient, recipient_len))
              {
                return 1;
              }
            }

            if (can_rollback_and_resync)
            {
              if (rollback_blockchain_and_resync())
              {
                // if by some way we fail to rollback and resync and we
                // fail to clear our sync request, then throw an assertion,
                // this should never happen...
                assert(!clear_sync_request(0));
              }
            }
          }
          else
          {
            if (validate_and_insert_block(message->block))
            {
              LOG_INFO("Received block at height: %d.", g_protocol_sync_entry.last_sync_height);
              if (check_sync_status())
              {
                if (request_sync_next_block(g_protocol_sync_entry.recipient, g_protocol_sync_entry.recipient_len))
                {
                  return 1;
                }
              }
            }
          }
        }
      }
      break;
    case PKT_TYPE_GET_NUM_TRANSACTIONS_REQ:
      {
        get_num_transactions_request_t *message = (get_num_transactions_request_t*)message_object;
        if (handle_packet_sendto(recipient, recipient_len, PKT_TYPE_GET_NUM_TRANSACTIONS_RESP,
          get_num_txs_in_mempool()))
        {
          return 1;
        }
      }
      break;
    case PKT_TYPE_GET_NUM_TRANSACTIONS_RESP:
      {
        get_num_transactions_response_t *message = (get_num_transactions_response_t*)message_object;
        if (message->num_transactions > 0)
        {
          if (handle_packet_sendto(recipient, recipient_len, PKT_TYPE_GET_ALL_TRANSACTION_IDS_REQ))
          {
            return 1;
          }
        }
      }
      break;
    case PKT_TYPE_GET_ALL_TRANSACTION_IDS_REQ:
      {
        get_all_transaction_ids_request_t *message = (get_all_transaction_ids_request_t*)message_object;
        if (handle_packet_sendto(recipient, recipient_len, PKT_TYPE_GET_ALL_TRANSACTION_IDS_RESP))
        {
          return 1;
        }
      }
      break;
    case PKT_TYPE_GET_ALL_TRANSACTION_IDS_RESP:
      {
        get_all_transaction_ids_response_t *message = (get_all_transaction_ids_response_t*)message_object;
        for (int i = 0; i >= message->num_transaction_ids; i++)
        {
          uint8_t *id = message->transaction_ids[i];
          transaction_t *transaction = get_tx_from_mempool(id);
          if (transaction != NULL)
          {
            continue;
          }

          if (handle_packet_sendto(recipient, recipient_len, PKT_TYPE_GET_TRANSACTION_REQ, id))
          {
            return 1;
          }
        }
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_REQ:
      {
        get_transaction_request_t *message = (get_transaction_request_t*)message_object;
        transaction_t *transaction = get_tx_from_mempool(message->id);
        if (!transaction)
        {
          return 1;
        }

        if (handle_packet_sendto(recipient, recipient_len, PKT_TYPE_GET_TRANSACTION_RESP, transaction))
        {
          return 1;
        }
      }
      break;
    case PKT_TYPE_GET_TRANSACTION_RESP:
      {
        get_transaction_response_t *message = (get_transaction_response_t*)message_object;
        add_tx_to_mempool(message->transaction);
      }
      break;
    default:
      LOG_DEBUG("Could not handle packet with unknown packet id: %d!", packet_id);
      return 1;
  }

  return 0;
}

int handle_receive_packet(pittacus_gossip_t *gossip, const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len, const uint8_t *data, size_t data_size)
{
  buffer_t *buffer = buffer_init_data(0, data, data_size);
  packet_t *packet = make_packet();
  if (deserialize_packet(packet, buffer))
  {
    buffer_free(buffer);
    return 1;
  }

  buffer_free(buffer);
  void *message = deserialize_message(packet);
  if (!message)
  {
    free_packet(packet);
    return 1;
  }

  if (handle_packet(gossip, recipient, recipient_len, packet->id, message))
  {
    free_message(packet->id, message);
    free_packet(packet);
    return 1;
  }

  free_message(packet->id, message);
  free_packet(packet);
  return 0;
}

int handle_send_packet(pittacus_gossip_t *gossip, const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len, int broadcast, uint32_t packet_id, va_list args)
{
  packet_t *packet = serialize_message(packet_id, args);
  if (!packet)
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
    result = net_send_data(gossip, (const uint8_t*)&raw_data, data_len);
  }
  else
  {
    result = net_data_sendto(gossip, recipient, recipient_len, (const uint8_t*)&raw_data, data_len);
  }

  return result;
}

int handle_packet_sendto(const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len, uint32_t packet_id, ...)
{
  va_list args;
  va_start(args, packet_id);
  if (handle_send_packet(net_get_gossip(), recipient, recipient_len, 0, packet_id, args))
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
  if (handle_send_packet(net_get_gossip(), NULL, 0, 1, packet_id, args))
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
    if (get_current_time() - g_protocol_sync_entry.last_sync_ts > RESYNC_BLOCK_REQUEST_DELAY)
    {
      uint32_t block_height = g_protocol_sync_entry.last_sync_height;
      request_sync_block(g_protocol_sync_entry.recipient, g_protocol_sync_entry.recipient_len, block_height, NULL);
    }
  }

  //handle_packet_broadcast(PKT_TYPE_GET_BLOCK_HEIGHT_REQ);
  //handle_packet_broadcast(PKT_TYPE_GET_NUM_TRANSACTIONS_REQ);
  return TASK_RESULT_WAIT;
}
