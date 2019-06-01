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
#include <stdint.h>
#include <assert.h>

#include <hashtable.h>

#include "common/logger.h"
#include "common/util.h"

#include "checkpoint_data.h"
#include "checkpoints.h"
#include "parameters.h"

#include "crypto/cryptoutil.h"

static int g_checkpoints_initialized = 0;
static HashTable *g_checkpoints_table = NULL;
static int g_num_checkpoints = 0;

int get_checkpoint_hash_from_height(uint32_t height, uint8_t **hash_out)
{
  void *val = NULL;
  if (hashtable_get(g_checkpoints_table, &height, &val) != CC_OK)
  {
    return 1;
  }

  *hash_out = val;
  return 0;
}

int has_checkpoint_hash_by_height(uint32_t height)
{
  uint8_t *checkpoint_hash = NULL;
  return get_checkpoint_hash_from_height(height, &checkpoint_hash) == 0;
}

int add_checkpoint(uint32_t height, uint8_t *hash)
{
  if (hashtable_add(g_checkpoints_table, &height, (void*)hash) != CC_OK)
  {
    return 1;
  }

  g_num_checkpoints++;
  return 0;
}

int remove_checkpoint(uint32_t height)
{
  if (hashtable_remove(g_checkpoints_table, &height, NULL) != CC_OK)
  {
    return 1;
  }

  g_num_checkpoints--;
  return 0;
}

static int load_checkpoint(checkpoint_entry_t checkpoint_entry)
{
  // convert block hash as hex back to bytes
  size_t hash_size = 0;
  uint8_t *hash = hex2bin(checkpoint_entry.block_hash, &hash_size);
  assert(hash_size == HASH_SIZE);

  // add hash as to checkpoint at height
  if (add_checkpoint(checkpoint_entry.height, hash))
  {
    return 1;
  }

  LOG_INFO("Loaded checkpoint: %s at block height: %u", checkpoint_entry.block_hash, checkpoint_entry.height);
  return 0;
}

int init_checkpoints(void)
{
  if (g_checkpoints_initialized)
  {
    return 1;
  }

  assert(hashtable_new(&g_checkpoints_table) == CC_OK);
  if (parameters_get_use_testnet())
  {
    for (int i = 0; i < NUM_TESTNET_CHECKPOINTS; i++)
    {
      checkpoint_entry_t checkpoint_entry = TESTNET_CHECKPOINTS[i];
      assert(load_checkpoint(checkpoint_entry) == 0);
    }
  }
  else
  {
    for (int i = 0; i < NUM_CHECKPOINTS; i++)
    {
      checkpoint_entry_t checkpoint_entry = CHECKPOINTS[i];
      assert(load_checkpoint(checkpoint_entry) == 0);
    }
  }

  g_checkpoints_initialized = 0;
  return 0;
}

int deinit_checkpoints(void)
{
  if (g_checkpoints_initialized == 0)
  {
    return 1;
  }

  hashtable_destroy(g_checkpoints_table);
  g_checkpoints_initialized = 0;
  return 0;
}
