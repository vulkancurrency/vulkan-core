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

#include <stdlib.h>
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

  /* Peers: */
  PKT_TYPE_CONNECT_REQ,
  PKT_TYPE_CONNECT_RESP,

  PKT_TYPE_GET_PEERLIST_REQ,
  PKT_TYPE_GET_PEERLIST_RESP,

  /* Blocks: */
  PKT_TYPE_GET_BLOCK_HEIGHT_REQ,
  PKT_TYPE_GET_BLOCK_HEIGHT_RESP,

  PKT_TYPE_GET_BLOCK_BY_HASH_REQ,
  PKT_TYPE_GET_BLOCK_BY_HASH_RESP,

  PKT_TYPE_GET_BLOCK_BY_HEIGHT_REQ,
  PKT_TYPE_GET_BLOCK_BY_HEIGHT_RESP,

  PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_REQ,
  PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HASH_RESP,

  PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_REQ,
  PKT_TYPE_GET_GROUPED_BLOCKS_FROM_HEIGHT_RESP,

  /* Transactions: */
  PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_REQ,
  PKT_TYPE_GET_BLOCK_NUM_TRANSACTIONS_RESP,

  PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_REQ,
  PKT_TYPE_GET_BLOCK_TRANSACTION_BY_HASH_RESP,

  PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_REQ,
  PKT_TYPE_GET_BLOCK_TRANSACTION_BY_INDEX_RESP,

  PKT_TYPE_INCOMING_MEMPOOL_TRANSACTION,
};

typedef struct
{
  uint32_t id;
  uint32_t size;
  uint8_t *data;
} packet_t;

typedef struct
{
  uint32_t host_port;
  char *version_number;
  char *version_name;
} connection_req_t;

typedef struct
{

} connection_resp_t;

typedef struct
{

} get_peerlist_req_t;

typedef struct
{
  uint32_t peerlist_data_size;
  uint8_t *peerlist_data;
} get_peerlist_resp_t;

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
  uint32_t height;
} get_grouped_blocks_from_height_request_t;

typedef struct
{
  uint32_t block_data_size;
  uint8_t *block_data;
} get_grouped_blocks_from_height_response_t;

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
  uint8_t *tx_hash;
} get_block_transaction_by_hash_request_t;

typedef struct
{
  uint8_t *block_hash;
  uint32_t tx_index;
  transaction_t *transaction;
} get_block_transaction_by_hash_response_t;

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
  net_connection_t *net_connection;

  int sync_initiated;
  int sync_did_backup_blockchain;
  int sync_finding_top_block;
  block_t *sync_pending_block;
  uint32_t sync_height;
  int32_t sync_start_height;

  int is_syncing_grouped_blocks;
  vec_void_t sync_pending_blocks;
  size_t sync_pending_blocks_count;

  uint32_t last_sync_height;
  uint32_t last_sync_ts;
  uint8_t last_sync_tries;

  int tx_sync_initiated;
  uint32_t tx_sync_num_txs;
  int32_t last_tx_sync_index;
  uint32_t last_tx_sync_ts;
  uint8_t last_tx_sync_tries;
} sync_entry_t;

void set_force_version_check(int force_version_check);
int get_force_version_check(void);

packet_t* make_packet(void);
int serialize_packet(buffer_t *buffer, packet_t *packet);
int deserialize_packet(packet_t *packet, buffer_iterator_t *buffer_iterator);
void free_packet(packet_t *packet);

int serialize_message(packet_t **packet, uint32_t packet_id, va_list args);
int deserialize_message(packet_t *packet, void **message);
void free_message(uint32_t packet_id, int did_packet_fail, void *message_object);

net_connection_t* get_sync_net_connection(void);
int get_sync_initiated(void);

int init_sync_request(int height, net_connection_t *net_connection);
int clear_sync_request(int sync_success);
int clear_tx_sync_request(void);
int clear_grouped_sync_request(void);

void handle_sync_started(void);
void handle_sync_added_block(void);
void handle_sync_stopped(void);
void handle_sync_completed(void);

int check_sync_status(int force_sync_complete);
int request_sync_block(net_connection_t *net_connection, uint32_t height, uint8_t *hash);
int request_sync_next_block(net_connection_t *net_connection);
int request_sync_previous_block(net_connection_t *net_connection);

int request_sync_transaction(net_connection_t *net_connection, uint8_t *block_hash, uint32_t tx_index, uint8_t *tx_hash);
int request_sync_next_transaction(net_connection_t *net_connection);

int block_header_received(net_connection_t *net_connection, block_t *block);
int block_header_sync_complete(net_connection_t *net_connection, block_t *block);
int transaction_received(net_connection_t *net_connection, transaction_t *transaction, uint32_t tx_index);
int backup_blockchain_and_rollback(void);

int can_packet_be_processed(net_connection_t *net_connection, uint32_t packet_id);
int handle_packet_anonymous(net_connection_t *net_connection, uint32_t packet_id, void *message_object);
int handle_packet(net_connection_t *net_connection, uint32_t packet_id, void *message_object);
int handle_receive_packet(net_connection_t *net_connection, packet_t *packet);

int handle_send_packet(net_connection_t *net_connection, int broadcast, uint32_t packet_id, va_list args);
int handle_packet_sendto(net_connection_t *net_connection, uint32_t packet_id, ...);
int handle_packet_broadcast(uint32_t packet_id, ...);

task_result_t resync_chain(task_t *task, va_list args);

#ifdef __cplusplus
}
#endif
