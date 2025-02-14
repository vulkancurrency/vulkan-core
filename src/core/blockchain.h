// Copyright (c) 2019-2022, The Vulkan Developers.
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

#ifdef USE_LEVELDB
#include <leveldb/c.h>
#else
#include <rocksdb/c.h>
#endif

#include "common/util.h"
#include "common/vec.h"
#include "common/vulkan.h"

#include "block.h"
#include "transaction.h"

VULKAN_BEGIN_DECL

#define DB_KEY_PREFIX_TX "tx"
#define DB_KEY_PREFIX_UNSPENT_TX "utx"
#define DB_KEY_PREFIX_BLOCK "bk"
#define DB_KEY_PREFIX_TOP_BLOCK "tbk"

#define DB_KEY_PREFIX_SIZE_TX 2
#define DB_KEY_PREFIX_SIZE_UNSPENT_TX 3
#define DB_KEY_PREFIX_SIZE_BLOCK 2
#define DB_KEY_PREFIX_SIZE_TOP_BLOCK 3

VULKAN_API int valid_compression_type(int compression_type);
VULKAN_API const char* get_compression_type_str(int compression_type);
VULKAN_API int get_compression_type_from_str(const char *compression_type_str);

VULKAN_API void set_want_blockchain_compression(int want_blockchain_compression);
VULKAN_API int get_want_blockchain_compression(void);

VULKAN_API void set_blockchain_compression_type(int compression_type);
VULKAN_API int get_blockchain_compression_type(void);

VULKAN_API const char* get_blockchain_dir(void);
VULKAN_API const char* get_blockchain_backup_dir(const char *blockchain_dir);

VULKAN_API int repair_blockchain(const char *blockchain_dir);
VULKAN_API int load_blockchain_top_block(void);
VULKAN_API int open_blockchain(const char *blockchain_dir, int load_top_block);
VULKAN_API int close_blockchain(void);

VULKAN_API int open_backup_blockchain(const char *blockchain_backup_dir);
VULKAN_API int close_backup_blockchain(void);

VULKAN_API int init_blockchain(const char *blockchain_dir, int load_top_block);
VULKAN_API int remove_blockchain(const char *blockchain_dir);

#ifdef USE_LEVELDB
VULKAN_API int purge_all_entries_from_database(leveldb_t *db);
#else
VULKAN_API int purge_all_entries_from_database(rocksdb_t *db);
#endif

#ifdef USE_LEVELDB
VULKAN_API int copy_all_entries_to_database(leveldb_t *from_db, leveldb_t *to_db);
#else
VULKAN_API int copy_all_entries_to_database(rocksdb_t *from_db, rocksdb_t *to_db);
#endif

VULKAN_API int reset_blockchain_nolock(void);
VULKAN_API int reset_blockchain(void);

VULKAN_API int backup_blockchain_nolock(void);
VULKAN_API int backup_blockchain(void);

VULKAN_API int restore_blockchain_nolock(void);
VULKAN_API int restore_blockchain(void);

VULKAN_API int rollback_blockchain_nolock(uint32_t rollback_height);
VULKAN_API int rollback_blockchain(uint32_t rollback_height);

VULKAN_API uint32_t get_block_height_nolock(void);
VULKAN_API uint32_t get_block_height(void);

VULKAN_API uint64_t get_cumulative_emission(void);
VULKAN_API uint64_t get_block_reward(uint32_t block_height, uint64_t cumulative_emission);

VULKAN_API uint32_t get_next_work_required_nolock(uint8_t *previous_hash);
VULKAN_API uint32_t get_next_work_required(uint8_t *previous_hash);

VULKAN_API int valid_block_median_timestamp(block_t *block);
VULKAN_API int valid_block_emission(block_t *block);

VULKAN_API int update_unspent_transaction(uint8_t *block_hash, transaction_t *tx);
VULKAN_API int update_unspent_transactions(block_t *block);

VULKAN_API int insert_block_nolock(block_t *block, int update_unspent_txs);
VULKAN_API int insert_block(block_t *block, int update_unspent_txs);

VULKAN_API int validate_and_insert_block_nolock(block_t *block);
VULKAN_API int validate_and_insert_block(block_t *block);

VULKAN_API int is_genesis_block(uint8_t *block_hash);

VULKAN_API block_t *get_block_from_hash_nolock(uint8_t *block_hash);
VULKAN_API block_t *get_block_from_hash(uint8_t *block_hash);

VULKAN_API block_t *get_block_from_height_nolock(uint32_t height);
VULKAN_API block_t *get_block_from_height(uint32_t height);

VULKAN_API int32_t get_block_height_from_hash_nolock(uint8_t *block_hash);
VULKAN_API int32_t get_block_height_from_hash(uint8_t *block_hash);

VULKAN_API int32_t get_block_height_from_block(block_t *block);
VULKAN_API uint8_t *get_block_hash_from_height(uint32_t height);

VULKAN_API int has_block_by_hash(uint8_t *block_hash);
VULKAN_API int has_block_by_height(uint32_t height);

VULKAN_API int insert_tx_into_index_nolock(uint8_t *block_hash, transaction_t *tx);
VULKAN_API int insert_tx_into_index(uint8_t *block_hash, transaction_t *tx);

VULKAN_API int insert_tx_into_unspent_index_nolock(transaction_t *tx);
VULKAN_API int insert_tx_into_unspent_index(transaction_t *tx);

VULKAN_API int insert_unspent_tx_into_index_nolock(unspent_transaction_t *unspent_tx);
VULKAN_API int insert_unspent_tx_into_index(unspent_transaction_t *unspent_tx);

VULKAN_API unspent_transaction_t *get_unspent_tx_from_index_nolock(uint8_t *tx_id);
VULKAN_API unspent_transaction_t *get_unspent_tx_from_index(uint8_t *tx_id);

VULKAN_API uint8_t *get_block_hash_from_tx_id_nolock(uint8_t *tx_id);
VULKAN_API uint8_t *get_block_hash_from_tx_id(uint8_t *tx_id);

VULKAN_API block_t *get_block_from_tx_id(uint8_t *tx_id);

VULKAN_API int delete_block_from_blockchain_nolock(uint8_t *block_hash);
VULKAN_API int delete_block_from_blockchain(uint8_t *block_hash);

VULKAN_API int delete_tx_from_index_nolock(uint8_t *tx_id);
VULKAN_API int delete_tx_from_index(uint8_t *tx_id);

VULKAN_API int delete_unspent_tx_from_index_nolock(uint8_t *tx_id);
VULKAN_API int delete_unspent_tx_from_index(uint8_t *tx_id);

VULKAN_API int set_top_block_hash_noblock(uint8_t *block_hash);
VULKAN_API int set_top_block_hash(uint8_t *block_hash);

VULKAN_API uint8_t* get_top_block_hash_noblock(void);
VULKAN_API uint8_t* get_top_block_hash(void);

VULKAN_API int set_top_block(block_t *block);
VULKAN_API block_t *get_top_block(void);

VULKAN_API int set_current_block_hash(uint8_t *hash);
VULKAN_API uint8_t *get_current_block_hash(void);

VULKAN_API int set_current_block(block_t *block);
VULKAN_API block_t *get_current_block(void);

VULKAN_API uint32_t get_blocks_since_hash(uint8_t *block_hash);
VULKAN_API uint32_t get_blocks_since_block(block_t *block);

VULKAN_API void get_tx_key(uint8_t *buffer, uint8_t *tx_id);
VULKAN_API void get_unspent_tx_key(uint8_t *buffer, uint8_t *tx_id);
VULKAN_API void get_block_key(uint8_t *buffer, uint8_t *block_hash);
VULKAN_API void get_top_block_key(uint8_t *buffer);

VULKAN_API int get_unspent_transactions_for_address_nolock(uint8_t *address, vec_void_t *unspent_txs, uint32_t *num_unspent_txs);
VULKAN_API int get_unspent_transactions_for_address(uint8_t *address, vec_void_t *unspent_txs, uint32_t *num_unspent_txs);

VULKAN_API uint64_t get_balance_for_address_nolock(uint8_t *address);
VULKAN_API uint64_t get_balance_for_address(uint8_t *address);

VULKAN_API double get_network_difficulty(void);
VULKAN_API double get_network_hashrate(void);
VULKAN_API double get_block_difficulty(block_t* block);
VULKAN_API uint32_t get_block_size(block_t* block);
VULKAN_API uint32_t get_block_version(void);
VULKAN_API transaction_t* create_coinbase_transaction(uint64_t reward);
VULKAN_API uint32_t get_current_time(void);

VULKAN_END_DECL
