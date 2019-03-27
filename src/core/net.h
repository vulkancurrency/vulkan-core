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

#include "common/mongoose.h"
#include "common/task.h"

#define NET_MGR_POLL_DELAY 1000

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct NetConnection
{
  struct mg_connection *connection;
  int anonymous;
} net_connnection_t;

net_connnection_t* init_net_connection(struct mg_connection *connection);
int free_net_connection(net_connnection_t *net_connnection);

net_connnection_t* get_net_connnection_nolock(struct mg_connection *connection);
net_connnection_t* get_net_connnection(struct mg_connection *connection);

int has_net_connnection_nolock(struct mg_connection *connection);
int has_net_connnection(struct mg_connection *connection);

int add_net_connnection_nolock(net_connnection_t *net_connnection);
int add_net_connnection(net_connnection_t *net_connnection);

int remove_net_connnection_nolock(net_connnection_t *net_connnection);
int remove_net_connnection(net_connnection_t *net_connnection);

int broadcast_data(net_connnection_t *net_connnection, uint8_t *data, size_t data_len);
int send_data(net_connnection_t *net_connnection, uint8_t *data, size_t data_len);
void data_received(net_connnection_t *net_connnection, uint8_t *data, size_t data_len);

void setup_net_port_mapping(int port);

int net_run(void);
int init_net(const char *address);
int deinit_net(void);

#ifdef __cplusplus
}
#endif
