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

#include "common/mongoose.h"
#include "common/task.h"

#include "block.h"
#include "transaction.h"
#include "net.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define RESYNC_CHAIN_TASK_DELAY 2
#define RESYNC_BLOCK_REQUEST_DELAY 10
#define RESYNC_BLOCK_MAX_TRIES 5

enum
{
  PKT_TYPE_UNKNOWN = 0,

  PKT_TYPE_CONNECT_REQ,
  PKT_TYPE_CONNECT_RESP,

  PKT_TYPE_INCOMING_BLOCK,
  PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION,

  PKT_TYPE_GET_BLOCK_HEIGHT_REQ,
  PKT_TYPE_GET_BLOCK_HEIGHT_RESP,

  PKT_TYPE_GET_BLOCK_BY_HASH_REQ,
  PKT_TYPE_GET_BLOCK_BY_HASH_RESP,

  PKT_TYPE_GET_BLOCK_BY_HEIGHT_REQ,
  PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP,

  PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ,
  PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP,

  PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ,
  PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP,

  PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ,
  PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP
};

typedef struct
{
  uint32_t id;
  uint32_t size;
  uint8_t *data;
} packet_t;

typedef struct
{

} connection_req_t;

typedef struct
{

} connection_resp_t;

typedef struct
{
  block_t *block;
} incoming_block_t;

typedef struct
{
  transaction_t *transaction;
} incoming_mempool_transaction_t;

typedef struct
{

} get_block_height_request_t;

typedef struct
{
  uint32_t height;
  uint8_t *hash;
} get_block_height_response_t;

typedef struct
{
  uint8_t *hash;
} get_block_by_hash_request_t;

typedef struct
{
  uint32_t height;
  block_t *block;
} get_block_by_hash_response_t;

typedef struct
{
  uint32_t height;
} get_block_by_height_request_t;

typedef struct
{
  uint8_t *hash;
  block_t *block;
} get_block_by_height_response_t;

typedef struct
{
  uint8_t *hash;
} get_block_num_transactions_request_t;

typedef struct
{
  uint8_t *hash;
  uint64_t num_transactions;
} get_block_num_transactions_response_t;

typedef struct
{
  uint8_t *block_hash;
  uint32_t tx_index;
} get_block_transaction_by_index_request_t;

typedef struct
{
  uint8_t *block_hash;
  uint32_t tx_index;
  transaction_t *transaction;
} get_block_transaction_by_index_response_t;

typedef struct SyncEntry
{
  net_connnection_t *net_connnection;

  int sync_initiated;
  int sync_did_backup_blockchain;
  int sync_finding_top_block;
  block_t *sync_pending_block;
  uint32_t sync_height;
  int32_t sync_start_height;

  uint32_t last_sync_height;
  uint32_t last_sync_ts;
  uint8_t last_sync_tries;

  int tx_sync_initiated;
  uint32_t tx_sync_num_txs;
  int32_t last_tx_sync_index;
  uint32_t last_tx_sync_ts;
  uint8_t last_tx_sync_tries;
} sync_entry_t;

packet_t* make_packet(void);
int serialize_packet(buffer_t *buffer, packet_t *packet);
int deserialize_packet(packet_t *packet, buffer_t *buffer);
int free_packet(packet_t *packet);

int serialize_message(packet_t **packet, uint32_t packet_id, va_list args);
int deserialize_message(packet_t *packet, void **message);
void free_message(uint32_t packet_id, void *message_object);

int init_sync_request(int height, net_connnection_t *net_connnection);
int clear_sync_request(int sync_success);
int check_sync_status(void);

int request_sync_block(net_connnection_t *net_connnection, uint32_t height, uint8_t *hash);
int request_sync_next_block(net_connnection_t *net_connnection);
int request_sync_previous_block(net_connnection_t *net_connnection);

int request_sync_transaction(net_connnection_t *net_connnection, uint8_t *block_hash, uint32_t tx_index, uint8_t *tx_hash);
int request_sync_next_transaction(net_connnection_t *net_connnection);

int block_header_received(net_connnection_t *net_connnection, block_t *block);
int block_header_sync_complete(net_connnection_t *net_connnection, block_t *block);
int rollback_blockchain_and_resync(void);

int handle_packet_anonymous(net_connnection_t *net_connnection, uint32_t packet_id, void *message_object);
int handle_packet(net_connnection_t *net_connnection, uint32_t packet_id, void *message_object);
int handle_receive_packet(net_connnection_t *net_connnection, const uint8_t *data, size_t data_size);

int handle_send_packet(net_connnection_t *net_connnection, int broadcast, uint32_t packet_id, va_list args);
int handle_packet_sendto(net_connnection_t *net_connnection, uint32_t packet_id, ...);
int handle_packet_broadcast(uint32_t packet_id, ...);

task_result_t resync_chain(task_t *task, va_list args);

#ifdef __cplusplus
}
#endif
