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

#include "common/buffer_iterator.h"
#include "common/buffer.h"
#include "common/mongoose.h"
#include "common/task.h"
#include "common/vec.h"
#include "common/vulkan.h"

#include "seed_nodes.h"

VULKAN_BEGIN_DECL

#define NET_MAX_NUM_CONNECTION_ENTRIES 1024
#define NET_MGR_POLL_DELAY 1000
#define NET_RECONNECT_SEEDS_TASK_DELAY 10
#define NET_FLUSH_CONNECTIONS_TASK_DELAY 0.01

typedef struct NetConnection
{
  struct mg_connection *connection;
  vec_void_t send_queue;
  size_t send_queue_size;

  int is_receiving_data;
  size_t expected_receiving_len;
  buffer_t *receiving_buffer;

  uint32_t host_port;
  int anonymous;
} net_connection_t;

typedef struct ConnectionEntry
{
  char *address;
  uint16_t port;
} connection_entry_t;

typedef struct ConnectionEntries
{
  uint16_t num_entries;
  connection_entry_t entries[NET_MAX_NUM_CONNECTION_ENTRIES];
} connection_entries_t;

VULKAN_API void set_net_host_address(const char *host_address);
VULKAN_API const char* get_net_host_address(void);

VULKAN_API void set_net_host_port(uint32_t host_port);
VULKAN_API uint32_t get_net_host_port(void);

VULKAN_API const char* get_net_external_address(void);

VULKAN_API void set_net_disable_port_mapping(int disable_port_mapping);
VULKAN_API int get_net_disable_port_mapping(void);

VULKAN_API const char* get_net_bind_address(void);

VULKAN_API net_connection_t* init_net_connection(struct mg_connection *connection);
VULKAN_API void free_net_connection(net_connection_t *net_connection);

VULKAN_API net_connection_t* get_net_connection_nolock(struct mg_connection *connection);
VULKAN_API net_connection_t* get_net_connection(struct mg_connection *connection);

VULKAN_API int has_net_connection_nolock(struct mg_connection *connection);
VULKAN_API int has_net_connection(struct mg_connection *connection);

VULKAN_API int add_net_connection_nolock(net_connection_t *net_connection);
VULKAN_API int add_net_connection(net_connection_t *net_connection);

VULKAN_API int remove_net_connection_nolock(net_connection_t *net_connection);
VULKAN_API int remove_net_connection(net_connection_t *net_connection);

VULKAN_API int close_net_connection(net_connection_t *net_connection);
VULKAN_API int connect_net_to_seeds(void);

VULKAN_API int broadcast_data(net_connection_t *net_connection, uint8_t *data, size_t data_len);
VULKAN_API int send_data(net_connection_t *net_connection, uint8_t *data, size_t data_len);
VULKAN_API void data_received(net_connection_t *net_connection, uint8_t *data, size_t data_len);

VULKAN_API void setup_net_port_mapping(uint16_t port);
VULKAN_API int connect_net_to_peer(const char *address, uint16_t port);

VULKAN_API int connect_seed_node(seed_node_entry_t seed_node_entry);
VULKAN_API int connect_net_to_seeds(void);

VULKAN_API int flush_send_queue(net_connection_t *net_connection);
VULKAN_API int flush_all_connections_nolock(void);
VULKAN_API int flush_all_connections(void);
VULKAN_API int flush_all_connections_noblock(void);

task_result_t reconnect_seeds(task_t *task, va_list args);
task_result_t flush_connections(task_t *task, va_list args);

VULKAN_API int net_run(void);
VULKAN_API int init_net(connection_entries_t connection_entries);
VULKAN_API int deinit_net(void);

VULKAN_END_DECL
