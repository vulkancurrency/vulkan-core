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

#include "common/buffer.h"
#include "common/mongoose.h"
#include "common/task.h"

#define NET_MGR_POLL_DELAY 1000
#define NET_RECONNECT_SEEDS_TASK_DELAY 10

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct NetConnection
{
  struct mg_connection *connection;

  int is_receiving_data;
  size_t expected_receiving_len;
  buffer_t *receiving_buffer;

  uint32_t host_port;
  int anonymous;
} net_connection_t;

void set_net_host_address(const char *host_address);
const char* get_net_host_address(void);

void set_net_host_port(uint32_t host_port);
uint32_t get_net_host_port(void);

void set_net_disable_port_mapping(int disable_port_mapping);
int get_net_disable_port_mapping(void);

const char* get_net_bind_address(void);

net_connection_t* init_net_connection(struct mg_connection *connection);
int free_net_connection(net_connection_t *net_connection);

net_connection_t* get_net_connection_nolock(struct mg_connection *connection);
net_connection_t* get_net_connection(struct mg_connection *connection);

int has_net_connection_nolock(struct mg_connection *connection);
int has_net_connection(struct mg_connection *connection);

int add_net_connection_nolock(net_connection_t *net_connection);
int add_net_connection(net_connection_t *net_connection);

int remove_net_connection_nolock(net_connection_t *net_connection);
int remove_net_connection(net_connection_t *net_connection);

int close_net_connection(net_connection_t *net_connection);
int connect_net_to_seeds(void);

int broadcast_data(net_connection_t *net_connection, uint8_t *data, size_t data_len);
int send_data(net_connection_t *net_connection, uint8_t *data, size_t data_len);

void data_received_nolock(net_connection_t *net_connection, uint8_t *data, size_t data_len);
void data_received(net_connection_t *net_connection, uint8_t *data, size_t data_len);

void setup_net_port_mapping(uint16_t port);
int connect_net_to_peer(const char *address, uint16_t port);

task_result_t reconnect_seeds(task_t *task, va_list args);

int net_run(void);
int init_net(void);
int deinit_net(void);

#ifdef __cplusplus
}
#endif
