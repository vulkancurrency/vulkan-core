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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include "genesis_block_loader.h"
#include "common/util.h"
#include "common/logger.h"

/**
 * Loads a genesis block from the JSON configuration file
 * network: "mainnet" or "testnet"
 * Returns 0 on success, -1 on failure
 */
int load_genesis_block_from_file(const char *filepath, const char *network, block_genesis_entry_t *genesis_entry)
{
  if (filepath == NULL || network == NULL || genesis_entry == NULL)
  {
    LOG_ERROR("Invalid arguments to load_genesis_block_from_file");
    return -1;
  }

  // Initialize genesis_entry fields
  memset(genesis_entry, 0, sizeof(block_genesis_entry_t));

  // Read JSON file into memory
  FILE *fp = fopen(filepath, "rb");
  if (fp == NULL)
  {
    LOG_ERROR("Failed to open genesis block config file: %s", filepath);
    return -1;
  }

  // Determine file size
  fseek(fp, 0, SEEK_END);
  long file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  if (file_size <= 0 || file_size > 1024 * 1024)  // Max 1MB
  {
    LOG_ERROR("Genesis config file size invalid: %ld bytes", file_size);
    fclose(fp);
    return -1;
  }

  // Read entire file
  char *file_content = (char *)malloc(file_size + 1);
  if (file_content == NULL)
  {
    LOG_ERROR("Memory allocation failed for reading genesis config");
    fclose(fp);
    return -1;
  }

  size_t bytes_read = fread(file_content, 1, file_size, fp);
  fclose(fp);

  if ((long)bytes_read != file_size)
  {
    LOG_ERROR("Failed to read genesis config file completely");
    free(file_content);
    return -1;
  }

  file_content[file_size] = '\0';

  // Parse JSON
  json_object *root = json_tokener_parse(file_content);
  free(file_content);

  if (root == NULL)
  {
    LOG_ERROR("Failed to parse JSON from genesis block config: %s", filepath);
    return -1;
  }

  // Get network object
  json_object *network_obj = json_object_object_get(root, network);
  if (network_obj == NULL)
  {
    LOG_ERROR("Network '%s' not found in genesis config", network);
    json_object_put(root);
    return -1;
  }

  // Extract version
  json_object *version_obj = json_object_object_get(network_obj, "version");
  if (version_obj == NULL)
  {
    LOG_ERROR("Missing 'version' field in genesis config");
    json_object_put(root);
    return -1;
  }
  genesis_entry->version = (uint32_t)json_object_get_int(version_obj);

  // Extract timestamp
  json_object *timestamp_obj = json_object_object_get(network_obj, "timestamp");
  if (timestamp_obj == NULL)
  {
    LOG_ERROR("Missing 'timestamp' field in genesis config");
    json_object_put(root);
    return -1;
  }
  genesis_entry->timestamp = (uint32_t)json_object_get_int(timestamp_obj);

  // Extract nonce
  json_object *nonce_obj = json_object_object_get(network_obj, "nonce");
  if (nonce_obj == NULL)
  {
    LOG_ERROR("Missing 'nonce' field in genesis config");
    json_object_put(root);
    return -1;
  }
  genesis_entry->nonce = (uint32_t)json_object_get_int(nonce_obj);

  // Extract bits
  json_object *bits_obj = json_object_object_get(network_obj, "bits");
  if (bits_obj == NULL)
  {
    LOG_ERROR("Missing 'bits' field in genesis config");
    json_object_put(root);
    return -1;
  }
  genesis_entry->bits = (uint32_t)json_object_get_int(bits_obj);

  // Extract cumulative_emission
  json_object *cumulative_obj = json_object_object_get(network_obj, "cumulative_emission");
  if (cumulative_obj == NULL)
  {
    LOG_ERROR("Missing 'cumulative_emission' field in genesis config");
    json_object_put(root);
    return -1;
  }
  genesis_entry->cumulative_emission = (uint64_t)json_object_get_int64(cumulative_obj);

  // Get and validate hash strings
  json_object *hash_obj = json_object_object_get(network_obj, "hash");
  json_object *prev_hash_obj = json_object_object_get(network_obj, "previous_hash");
  json_object *merkle_obj = json_object_object_get(network_obj, "merkle_root");

  if (hash_obj == NULL || prev_hash_obj == NULL || merkle_obj == NULL)
  {
    LOG_ERROR("Missing required hash fields (hash, previous_hash, merkle_root) in genesis config");
    json_object_put(root);
    return -1;
  }

  const char *hash_str = json_object_get_string(hash_obj);
  const char *prev_hash_str = json_object_get_string(prev_hash_obj);
  const char *merkle_str = json_object_get_string(merkle_obj);

  if (hash_str == NULL || prev_hash_str == NULL || merkle_str == NULL)
  {
    LOG_ERROR("Hash fields contain null values in genesis config");
    json_object_put(root);
    return -1;
  }

  // Validate hex string lengths (should be 64 chars for 32-byte hash)
  if (strlen(hash_str) != 64 || strlen(prev_hash_str) != 64 || strlen(merkle_str) != 64)
  {
    LOG_ERROR("Invalid hash string length in genesis config (expected 64 chars each): hash=%lu, prev_hash=%lu, merkle=%lu",
      strlen(hash_str), strlen(prev_hash_str), strlen(merkle_str));
    json_object_put(root);
    return -1;
  }

  // Allocate memory and copy strings
  genesis_entry->hash_str = (char *)malloc(strlen(hash_str) + 1);
  genesis_entry->previous_hash_str = (char *)malloc(strlen(prev_hash_str) + 1);
  genesis_entry->merkle_root_str = (char *)malloc(strlen(merkle_str) + 1);

  if (genesis_entry->hash_str == NULL || genesis_entry->previous_hash_str == NULL || genesis_entry->merkle_root_str == NULL)
  {
    LOG_ERROR("Memory allocation failed for genesis block strings");
    free(genesis_entry->hash_str);
    free(genesis_entry->previous_hash_str);
    free(genesis_entry->merkle_root_str);
    genesis_entry->hash_str = NULL;
    genesis_entry->previous_hash_str = NULL;
    genesis_entry->merkle_root_str = NULL;
    json_object_put(root);
    return -1;
  }

  strcpy(genesis_entry->hash_str, hash_str);
  strcpy(genesis_entry->previous_hash_str, prev_hash_str);
  strcpy(genesis_entry->merkle_root_str, merkle_str);

  json_object_put(root);

  LOG_INFO("Successfully loaded genesis block configuration for network: %s (timestamp=%u, nonce=%u)",
    network, genesis_entry->timestamp, genesis_entry->nonce);
  return 0;
}

/**
 * Frees allocated memory in genesis_entry
 */
void free_genesis_block_entry(block_genesis_entry_t *genesis_entry)
{
  if (genesis_entry != NULL)
  {
    free(genesis_entry->hash_str);
    free(genesis_entry->previous_hash_str);
    free(genesis_entry->merkle_root_str);
    genesis_entry->hash_str = NULL;
    genesis_entry->previous_hash_str = NULL;
    genesis_entry->merkle_root_str = NULL;
  }
}
