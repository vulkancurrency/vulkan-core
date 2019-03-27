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

#include <stdint.h>
#include <assert.h>

#include "common/vec.h"

#include "p2p.h"

static int g_p2p_initialized = 0;
static mtx_t g_p2p_lock;
static vec_void_t g_p2p_peerlist;
static int g_next_peer_id = -1;
static int g_num_peers = 0;

peer_t* init_peer(net_connnection_t *net_connnection)
{
  assert(net_connnection != NULL);
  g_next_peer_id++;
  peer_t *peer = malloc(sizeof(peer_t));
  peer->id = g_next_peer_id;
  peer->net_connnection = net_connnection;
  return peer;
}

int free_peer(peer_t *peer)
{
  assert(peer != NULL);
  free(peer);
  return 0;
}

peer_t* get_peer_nolock(uint64_t peer_id)
{
  void *value = NULL;
  int index = 0;
  vec_foreach(&g_p2p_peerlist, value, index)
  {
    peer_t *peer = (peer_t*)value;
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

int add_peer_nolock(peer_t *peer)
{
  assert(peer != NULL);
  if (has_peer(peer->id))
  {
    return 1;
  }

  assert(vec_push(&g_p2p_peerlist, peer) == 0);
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

  vec_remove(&g_p2p_peerlist, peer);
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

int broadcast_data_to_peers_nolock(net_connnection_t *net_connnection, uint8_t *data, size_t data_len)
{
  assert(net_connnection != NULL);
  void *value = NULL;
  int index = 0;
  vec_foreach(&g_p2p_peerlist, value, index)
  {
    peer_t *peer = (peer_t*)value;
    assert(peer != NULL);

    // do not relay this message back to the sender, as we are intended to relay
    // this message to all other peers in our peerlist...
    if (peer->net_connnection == net_connnection)
    {
      continue;
    }

    if (send_data(peer->net_connnection, data, data_len))
    {
      return 1;
    }
  }

  return 0;
}

int broadcast_data_to_peers(net_connnection_t *net_connnection, uint8_t *data, size_t data_len)
{
  mtx_lock(&g_p2p_lock);
  int result = broadcast_data_to_peers_nolock(net_connnection, data, data_len);
  mtx_unlock(&g_p2p_lock);
  return result;
}

int init_p2p(void)
{
  if (g_p2p_initialized)
  {
    return 1;
  }

  mtx_init(&g_p2p_lock, mtx_recursive);
  vec_init(&g_p2p_peerlist);
  g_p2p_initialized = 1;
  return 0;
}

int deinit_p2p(void)
{
  if (g_p2p_initialized == 0)
  {
    return 1;
  }

  vec_deinit(&g_p2p_peerlist);
  mtx_destroy(&g_p2p_lock);
  g_next_peer_id = -1;
  g_num_peers = 0;
  g_p2p_initialized = 0;
  return 0;
}
