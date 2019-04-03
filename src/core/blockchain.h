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

#include "block.h"
#include "transaction.h"

#include "common/util.h"
#include "common/vec.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define DB_KEY_PREFIX_TX "t"
#define DB_KEY_PREFIX_UNSPENT_TX "ut"
#define DB_KEY_PREFIX_BLOCK "b"
#define DB_KEY_PREFIX_TOP_BLOCK "tb"

#define DB_KEY_PREFIX_SIZE_TX 1
#define DB_KEY_PREFIX_SIZE_UNSPENT_TX 2
#define DB_KEY_PREFIX_SIZE_BLOCK 1
#define DB_KEY_PREFIX_SIZE_TOP_BLOCK 2

const char* get_blockchain_dir(void);
const char* get_blockchain_backup_dir(const char *blockchain_dir);

int open_blockchain(const char *blockchain_dir);
int close_blockchain(void);

int open_backup_blockchain(void);
int close_backup_blockchain(void);

int init_blockchain(const char *blockchain_dir);
int remove_blockchain(const char *blockchain_dir);

int backup_blockchain_nolock(void);
int backup_blockchain(void);

int restore_blockchain_nolock(void);
int restore_blockchain(void);

int rollback_blockchain_nolock(uint32_t rollback_height);
int rollback_blockchain(uint32_t rollback_height);

uint32_t get_block_height(void);

uint64_t get_cumulative_emission(void);
uint64_t get_block_reward(uint32_t block_height, uint64_t cumulative_emission);

uint64_t get_block_cumulative_difficulty(uint32_t block_height);

uint64_t get_block_difficulty_nolock(uint32_t block_height);
uint64_t get_block_difficulty(uint32_t block_height);

uint64_t get_next_block_difficulty(void);

int valid_block_median_timestamp(block_t *block);
int valid_block_emission(block_t *block, uint32_t block_height);

int insert_block_nolock(block_t *block);
int insert_block(block_t *block);

int validate_and_insert_block_nolock(block_t *block);
int validate_and_insert_block(block_t *block);

block_t *get_block_from_hash(uint8_t *block_hash);
block_t *get_block_from_height(uint32_t height);

int32_t get_block_height_from_hash(uint8_t *block_hash);
int32_t get_block_height_from_block(block_t *block);
uint8_t *get_block_hash_from_height(uint32_t height);

int has_block_by_hash(uint8_t *block_hash);
int has_block_by_height(uint32_t height);

int insert_tx_into_index(uint8_t *block_key, transaction_t *tx);
int insert_tx_into_unspent_index(transaction_t *tx);
int insert_unspent_tx_into_index(unspent_transaction_t *unspent_tx);
unspent_transaction_t *get_unspent_tx_from_index(uint8_t *tx_id);

uint8_t *get_block_hash_from_tx_id(uint8_t *tx_id);
block_t *get_block_from_tx_id(uint8_t *tx_id);

int delete_block_from_blockchain(uint8_t *block_hash);
int delete_tx_from_index(uint8_t *tx_id);
int delete_unspent_tx_from_index(uint8_t *tx_id);

int set_top_block_hash(uint8_t *block_hash);
uint8_t* get_top_block_hash(void);
int set_top_block(block_t *block);
block_t *get_top_block(void);

int set_current_block_hash(uint8_t *hash);
uint8_t *get_current_block_hash(void);
int set_current_block(block_t *block);
block_t *get_current_block(void);

uint32_t get_blocks_since_hash(uint8_t *block_hash);
uint32_t get_blocks_since_block(block_t *block);

int get_tx_key(uint8_t *buffer, uint8_t *tx_id);
int get_unspent_tx_key(uint8_t *buffer, uint8_t *tx_id);
int get_block_key(uint8_t *buffer, uint8_t *block_hash);
int get_top_block_key(uint8_t *buffer);

int get_unspent_transactions_for_address_nolock(uint8_t *address, vec_void_t *unspent_txs, uint32_t *num_unspent_txs);
int get_unspent_transactions_for_address(uint8_t *address, vec_void_t *unspent_txs, uint32_t *num_unspent_txs);

uint64_t get_balance_for_address_nolock(uint8_t *address);
uint64_t get_balance_for_address(uint8_t *address);

int get_unspent_transactions_for_wallet_nolock(wallet_t *wallet, vec_void_t *unspent_txs, uint32_t *num_unspent_txs);
int get_unspent_transactions_for_wallet(wallet_t *wallet, vec_void_t *unspent_txs, uint32_t *num_unspent_txs);

uint64_t get_balance_for_wallet_nolock(wallet_t *wallet);
uint64_t get_balance_for_wallet(wallet_t *wallet);

#ifdef __cplusplus
}
#endif
