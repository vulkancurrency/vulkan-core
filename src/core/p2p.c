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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <cc_hashtable.h>

#include "common/task.h"
#include "common/buffer.h"
#include "common/buffer_iterator.h"
#include "common/buffer_storage.h"
#include "common/util.h"
#include "common/logger.h"

#include "net.h"
#include "p2p.h"
#include "parameters.h"

static int g_p2p_initialized = 0;
static mtx_t g_p2p_lock;

static const char *g_p2p_storage_filename = "p2p_peerlist_storage.dat";
static buffer_storage_t *g_p2p_storage_db = NULL;

static CC_HashTable* g_p2p_peerlist_table = NULL;
static int g_num_peers = 0;
static task_t *g_p2p_storage_save_task = NULL;

void set_p2p_storage_filename(const char *storage_filename)
{
  g_p2p_storage_filename = storage_filename;
}

const char *get_p2p_storage_filename(void)
{
  return g_p2p_storage_filename;
}

peer_t* init_peer(uint64_t peer_id, net_connection_t *net_connection)
{
  assert(net_connection != NULL);
  peer_t *peer = malloc(sizeof(peer_t));
  assert(peer != NULL);
  peer->id = peer_id;
  peer->net_connection = net_connection;
  return peer;
}

void free_peer(peer_t *peer)
{
  assert(peer != NULL);
  free(peer);
}

peer_t* get_peer_nolock(uint64_t peer_id)
{
  CC_HashTableIter iter;
  cc_hashtable_iter_init(&iter, g_p2p_peerlist_table);

  void *el;
  while (cc_hashtable_iter_next(&iter, (void*) &el) != CC_ITER_END)
  {
    peer_t *peer = *(peer_t**)el;
    assert(peer != NULL);

    if (peer->id == peer_id)
    {
      return peer;
    }
  }

  return NULL;
}

peer_t* get_peer(uint64_t peer_id)
{
  mtx_lock(&g_p2p_lock);
  peer_t *peer = get_peer_nolock(peer_id);
  mtx_unlock(&g_p2p_lock);
  return peer;
}

peer_t* get_peer_from_net_connection_nolock(net_connection_t *net_connection)
{
  assert(net_connection != NULL);
  CC_HashTableIter iter;
  cc_hashtable_iter_init(&iter, g_p2p_peerlist_table);

  void *el;
  while (cc_hashtable_iter_next(&iter, (void*) &el) != CC_ITER_END)
  {
    peer_t *peer = *(peer_t**)el;
    assert(peer != NULL);

    if (peer->net_connection == net_connection)
    {
      return peer;
    }
  }

  return NULL;
}

peer_t* get_peer_from_net_connection(net_connection_t *net_connection)
{
  mtx_lock(&g_p2p_lock);
  peer_t *peer = get_peer_from_net_connection_nolock(net_connection);
  mtx_unlock(&g_p2p_lock);
  return peer;
}

int has_peer_nolock(uint64_t peer_id)
{
  return get_peer_nolock(peer_id) != NULL;
}

int has_peer(uint64_t peer_id)
{
  mtx_lock(&g_p2p_lock);
  int result = has_peer_nolock(peer_id);
  mtx_unlock(&g_p2p_lock);
  return result;
}

uint16_t get_num_peers(void)
{
  return g_num_peers;
}

int add_peer_nolock(peer_t *peer)
{
  assert(peer != NULL);
  if (has_peer(peer->id))
  {
    return 1;
  }

  if (g_num_peers >= MAX_P2P_PEERS_COUNT)
  {
    return 1;
  }

  assert(cc_hashtable_add(g_p2p_peerlist_table, &peer->id, peer) == CC_OK);
  g_num_peers++;
  return 0;
}

int add_peer(peer_t *peer)
{
  mtx_lock(&g_p2p_lock);
  int result = add_peer_nolock(peer);
  mtx_unlock(&g_p2p_lock);
  return result;
}

int remove_peer_nolock(peer_t *peer)
{
  assert(peer != NULL);
  if (has_peer(peer->id) == 0)
  {
    return 1;
  }

  assert(cc_hashtable_remove(g_p2p_peerlist_table, &peer->id, NULL) == CC_OK);
  g_num_peers--;
  return 0;
}

int remove_peer(peer_t *peer)
{
  mtx_lock(&g_p2p_lock);
  int result = remove_peer_nolock(peer);
  mtx_unlock(&g_p2p_lock);
  return result;
}

int serialize_peerlist_nolock(buffer_t *buffer)
{
  assert(buffer != NULL);
  if (buffer_write_uint16(buffer, g_num_peers))
  {
    return 1;
  }

  CC_HashTableIter iter;
  cc_hashtable_iter_init(&iter, g_p2p_peerlist_table);

  void *el;
  while (cc_hashtable_iter_next(&iter, (void*) &el) != CC_ITER_END)
  {
    peer_t *peer = *(peer_t**)el;
    assert(peer != NULL);

    net_connection_t *net_connection = peer->net_connection;
    assert(net_connection != NULL);

    struct mg_connection *connection = net_connection->connection;
    assert(connection != NULL);

    uint32_t remote_ip = ntohl(*(uint32_t*)&connection->sa.sin.sin_addr);
    if (buffer_write_uint32(buffer, remote_ip))
    {
      return 1;
    }

    if (buffer_write_uint16(buffer, net_connection->host_port))
    {
      return 1;
    }
  }

  return 0;
}

int serialize_peerlist(buffer_t *buffer)
{
  assert(buffer != NULL);
  mtx_lock(&g_p2p_lock);
  int result = serialize_peerlist_nolock(buffer);
  mtx_unlock(&g_p2p_lock);
  return result;
}

int deserialize_peerlist_noblock(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  uint16_t num_peers = 0;
  if (buffer_read_uint16(buffer_iterator, &num_peers))
  {
    return 1;
  }

  for (uint16_t i = 0; i < num_peers; i++)
  {
    uint32_t remote_ip = 0;
    if (buffer_read_uint32(buffer_iterator, &remote_ip))
    {
      return 1;
    }

    uint16_t host_port = 0;
    if (buffer_read_uint16(buffer_iterator, &host_port))
    {
      return 1;
    }

    if (remote_ip == convert_str_to_ip(get_net_external_address()) && host_port == get_net_host_port())
    {
      continue;
    }
    else if (remote_ip == convert_str_to_ip(get_net_host_address()) && host_port == get_net_host_port())
    {
      continue;
    }
    else if (is_local_address(remote_ip) || is_private_address(remote_ip))
    {
      continue;
    }

    char *bind_address = convert_ip_to_str(remote_ip);
    uint64_t peer_id = concatenate(remote_ip, host_port);
    if (has_peer(peer_id))
    {
      continue;
    }

    if (g_num_peers >= MAX_P2P_PEERS_COUNT)
    {
      break;
    }

    if (connect_net_to_peer(bind_address, host_port))
    {
      return 1;
    }

    free(bind_address);
  }

  return 0;
}

int deserialize_peerlist(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  mtx_lock(&g_p2p_lock);
  int result = deserialize_peerlist_noblock(buffer_iterator);
  mtx_unlock(&g_p2p_lock);
  return result;
}

int deserialize_peerlist_from_storage(buffer_t *buffer)
{
  assert(buffer != NULL);
  if (buffer_get_size(buffer) == 0)
  {
    return 1;
  }

  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);
  assert(buffer_iterator != NULL);

  if (deserialize_peerlist(buffer_iterator))
  {
    buffer_iterator_free(buffer_iterator);
    return 1;
  }

  buffer_iterator_free(buffer_iterator);
  return 0;
}

int broadcast_data_to_peers_nolock(net_connection_t *net_connection, const uint8_t *data, size_t data_len)
{
  assert(net_connection != NULL);
  assert(data != NULL);

  CC_HashTableIter iter;
  cc_hashtable_iter_init(&iter, g_p2p_peerlist_table);

  void *el;
  while (cc_hashtable_iter_next(&iter, (void*) &el) != CC_ITER_END)
  {
    peer_t *peer = *(peer_t**)el;
    assert(peer != NULL);

    if (peer->net_connection == net_connection)
    {
      continue;
    }

    if (send_data(peer->net_connection, data, data_len))
    {
      return 1;
    }
  }

  return 0;
}

int broadcast_data_to_peers(net_connection_t *net_connection, const uint8_t *data, size_t data_len)
{
  mtx_lock(&g_p2p_lock);
  int result = broadcast_data_to_peers_nolock(net_connection, data, data_len);
  mtx_unlock(&g_p2p_lock);
  return result;
}

static task_result_t save_peerlist_storage(task_t *task)
{
  LOG_INFO("Saving peerlist data...");
  buffer_t *buffer = buffer_init();
  if (serialize_peerlist(buffer))
  {
    perror("Failed to save P2P peerlist data, could not serialize peerlist to buffer!");
  }

  // write the serialized peer list data to the storage db
  char *err = NULL;
  if (buffer_storage_write_buffer(g_p2p_storage_db, buffer, &err))
  {
    perror(err);
  }

  LOG_INFO("Successfully saved peerlist data.");
  return TASK_RESULT_WAIT;
}

void print_p2p_list(void)
{
  printf("P2P List:\n");

  CC_HashTableIter iter;
  cc_hashtable_iter_init(&iter, g_p2p_peerlist_table);

  void *el;
  while (cc_hashtable_iter_next(&iter, (void*) &el) != CC_ITER_END)
  {
    peer_t *peer = *(peer_t**)el;
    assert(peer != NULL);

    net_connection_t *net_connection = peer->net_connection;
    assert(net_connection != NULL);

    struct mg_connection *connection = net_connection->connection;
    assert(connection != NULL);

    printf("Peer: %llu\n", peer->id);
  }
}

int init_p2p(void)
{
  if (g_p2p_initialized)
  {
    return 1;
  }

  mtx_init(&g_p2p_lock, mtx_recursive);
  assert(cc_hashtable_new(&g_p2p_peerlist_table) == CC_OK);

  char *err = NULL;
  g_p2p_storage_db = buffer_storage_open(g_p2p_storage_filename, &err);
  if (err != NULL)
  {
    LOG_ERROR("Failed to initialize P2P storage db: %s", err);
    return 1;
  }

  buffer_t *buffer = NULL;
  if (buffer_storage_read_buffer(g_p2p_storage_db, &buffer, &err))
  {
    LOG_ERROR("Failed to deserialize initialize P2P storage db: %s", err);
    return 1;
  }

  // attempt to load the peer list data
  deserialize_peerlist_from_storage(buffer);
  buffer_free(buffer);
  LOG_INFO("Successfully opened p2p storage db: %s", g_p2p_storage_filename);

  // setup a new task for saving the peer list data on an interval
  g_p2p_storage_save_task = add_task(save_peerlist_storage, SAVE_PEER_LIST_STORAGE_DELAY);
  g_p2p_initialized = 1;
  return 0;
}

size_t get_connected_peers(peer_t*** out_peers) {
    mtx_lock(&g_p2p_lock);
    
    size_t num_peers = get_num_peers();
    if (num_peers == 0) {
        mtx_unlock(&g_p2p_lock);
        *out_peers = NULL;
        return 0;
    }
    
    // Allocate array for peer pointers
    peer_t** peers = malloc(sizeof(peer_t*) * num_peers);
    size_t idx = 0;
    
    // Copy connected peers from hashtable
    CC_HashTableIter iter;
    cc_hashtable_iter_init(&iter, g_p2p_peerlist_table);
    
    void* el;
    while (cc_hashtable_iter_next(&iter, (void*)&el) != CC_ITER_END) {
        peer_t* peer = *(peer_t**)el;
        if (peer) {
            peers[idx++] = peer;
        }
    }
    
    mtx_unlock(&g_p2p_lock);
    *out_peers = peers;
    return idx;
}

int deinit_p2p(void)
{
  if (g_p2p_initialized == 0)
  {
    return 1;
  }

  remove_task(g_p2p_storage_save_task);
  cc_hashtable_destroy(g_p2p_peerlist_table);
  mtx_destroy(&g_p2p_lock);

  if (buffer_storage_close(g_p2p_storage_db))
  {
    LOG_ERROR("Failed to close P2P storage db!");
    return 1;
  }

  g_num_peers = 0;
  g_p2p_initialized = 0;
  return 0;
}
