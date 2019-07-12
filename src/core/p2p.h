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
#include <assert.h>

#include "common/buffer.h"
#include "common/buffer_iterator.h"
#include "common/vulkan.h"

#include "net.h"

VULKAN_BEGIN_DECL

typedef struct Peer
{
  uint64_t id;
  net_connection_t *net_connection;
} peer_t;

VULKAN_API peer_t* init_peer(uint64_t peer_id, net_connection_t *net_connection);
VULKAN_API void free_peer(peer_t *peer);

VULKAN_API peer_t* get_peer_nolock(uint64_t peer_id);
VULKAN_API peer_t* get_peer(uint64_t peer_id);

VULKAN_API peer_t* get_peer_from_net_connection_nolock(net_connection_t *net_connection);
VULKAN_API peer_t* get_peer_from_net_connection(net_connection_t *net_connection);

VULKAN_API int has_peer_nolock(uint64_t peer_id);
VULKAN_API int has_peer(uint64_t peer_id);

VULKAN_API uint16_t get_num_peers(void);

VULKAN_API int add_peer_nolock(peer_t *peer);
VULKAN_API int add_peer(peer_t *peer);

VULKAN_API int remove_peer_nolock(peer_t *peer);
VULKAN_API int remove_peer(peer_t *peer);

VULKAN_API int serialize_peerlist_nolock(buffer_t *buffer);
VULKAN_API int serialize_peerlist(buffer_t *buffer);

VULKAN_API int deserialize_peerlist_noblock(buffer_iterator_t *buffer_iterator);
VULKAN_API int deserialize_peerlist(buffer_iterator_t *buffer_iterator);

VULKAN_API int broadcast_data_to_peers_nolock(net_connection_t *net_connection, uint8_t *data, size_t data_len);
VULKAN_API int broadcast_data_to_peers(net_connection_t *net_connection, uint8_t *data, size_t data_len);

VULKAN_API int init_p2p(void);
VULKAN_API int deinit_p2p(void);

VULKAN_END_DECL
