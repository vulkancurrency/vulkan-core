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

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#include <gossip.h>
#include <config.h>

#include "common/logger.h"
#include "common/task.h"
#include "common/tinycthread.h"

#include "core/blockchainparams.h"
#include "core/net.h"
#include "core/protocol.h"
#include "core/version.h"

static int g_net_server_running = 0;
static int g_net_seed_mode = 0;
static int g_net_disable_port_mapping = 0;
static const char* g_net_bind_address = "0.0.0.0";
static int g_net_bind_port = P2P_PORT;

static pittacus_gossip_t *g_net_gossip = NULL;
static task_t *g_net_resync_chain_task = NULL;

static mtx_t g_net_recv_mutex;

void net_set_gossip(pittacus_gossip_t *gossip)
{
  g_net_gossip = gossip;
}

pittacus_gossip_t* net_get_gossip(void)
{
  return g_net_gossip;
}

void net_set_disable_port_mapping(int disable_port_mapping)
{
  g_net_disable_port_mapping = disable_port_mapping;
}

int net_get_disable_port_mapping(void)
{
  return g_net_disable_port_mapping;
}

void net_set_bind_address(const char *bind_address)
{
  g_net_bind_address = bind_address;
}

const char* net_get_bind_address(void)
{
  return g_net_bind_address;
}

void net_set_bind_port(int bind_port)
{
  g_net_bind_port = bind_port;
}

int net_get_bind_port(void)
{
  return g_net_bind_port;
}

void net_setup_port_mapping(int port)
{
  LOG_INFO("Tring to add IGD port mapping...");
  int result;

#if MINIUPNPC_API_VERSION > 13
  unsigned char ttl = 2;
  struct UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, 0, ttl, &result);
#else
  struct UPNPDev* deviceList = upnpDiscover(1000, NULL, NULL, 0, 0, &result);
#endif

  struct UPNPUrls urls;
  struct IGDdatas igdData;
  char lanAddress[64];
  result = UPNP_GetValidIGD(deviceList, &urls, &igdData, lanAddress, sizeof lanAddress);
  freeUPNPDevlist(deviceList);

  if (result > 0)
  {
    if (result == 1)
    {
      char *port_string = malloc(sizeof(port));
      sprintf(port_string, "%d", port);

      UPNP_DeletePortMapping(urls.controlURL, igdData.first.servicetype, port_string, "UDP", 0);
      int portMappingResult = UPNP_AddPortMapping(urls.controlURL, igdData.first.servicetype,
        port_string, port_string, lanAddress, APPLICATION_NAME, "UDP", 0, "0");

      if (portMappingResult != 0)
      {
        LOG_WARNING("Failed to add IGD port mapping!");
      }
      else
      {
        LOG_INFO("Added IGD port mapping.");
      }

      free(port_string);
    }
    else if (result == 2)
    {
      LOG_WARNING("Failed to add IGD port mapping, could not connect IGD port mapping!");
    }
    else if (result == 3)
    {
      LOG_WARNING("Failed to add IGD port mapping, UPnP device was not recoginzed as IGD!");
    }
    else
    {
      LOG_WARNING("Failed to add IGD port mapping, invalid code returned: %d!", result);
    }

    FreeUPNPUrls(&urls);
  }
  else
  {
    LOG_WARNING("Failed to add IGD port mapping, UPnP device was not recoginzed as IGD!");
  }
}

void net_receive_data(void *context, pittacus_gossip_t *gossip, const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len, const uint8_t *data, size_t data_size)
{
  mtx_lock(&g_net_recv_mutex);
  if (handle_receive_packet(gossip, recipient, recipient_len, data, data_size))
  {
    LOG_DEBUG("Failed to handle an incoming packet!");
  }

  mtx_unlock(&g_net_recv_mutex);
}

int net_send_data(pittacus_gossip_t *gossip, const uint8_t *data, size_t data_size)
{
  return pittacus_gossip_send_data(gossip, data, data_size);
}

int net_data_sendto(pittacus_gossip_t *gossip, const pt_sockaddr_storage *recipient, pt_socklen_t recipient_len, const uint8_t *data, size_t data_size)
{
  return pittacus_gossip_data_sendto(gossip, recipient, recipient_len, data, data_size);
}

int net_connect(const char *address, int port)
{
  struct sockaddr_in self_in;
  self_in.sin_family = AF_INET;
  self_in.sin_port = 0;
  inet_aton(g_net_bind_address, &self_in.sin_addr);

  pittacus_addr_t self_addr = {
    .addr = (const pt_sockaddr *) &self_in,
    .addr_len = sizeof(struct sockaddr_in)
  };

  if (!g_net_disable_port_mapping)
  {
    net_setup_port_mapping(ntohs(self_in.sin_port));
  }

  pittacus_gossip_t *gossip = pittacus_gossip_create(&self_addr, &net_receive_data, NULL);
  if (gossip == NULL)
  {
    LOG_ERROR("Gossip initialization failed: %s!", strerror(errno));
    return 1;
  }

  struct sockaddr_in seed_node_in;
  seed_node_in.sin_family = AF_INET;
  seed_node_in.sin_port = htons(port);
  inet_aton(address, &seed_node_in.sin_addr);

  pittacus_addr_t seed_node_addr = {
    .addr = (const pt_sockaddr *) &seed_node_in,
    .addr_len = sizeof(struct sockaddr_in)
  };

  int join_result = pittacus_gossip_join(gossip, &seed_node_addr, 1);
  if (join_result < 0)
  {
    LOG_ERROR("Gossip join failed: %d!", join_result);
    pittacus_gossip_destroy(gossip);
    return 1;
  }

  g_net_gossip = gossip;
  return 0;
}

int net_open_connection(void)
{
  if (!g_net_disable_port_mapping)
  {
    net_setup_port_mapping(g_net_bind_port);
  }

  struct sockaddr_in self_in;
  self_in.sin_family = AF_INET;
  self_in.sin_port = htons(g_net_bind_port);
  inet_aton(g_net_bind_address, &self_in.sin_addr);

  pittacus_addr_t self_addr = {
    .addr = (const pt_sockaddr *) &self_in,
    .addr_len = sizeof(struct sockaddr_in)
  };

  pittacus_gossip_t *gossip = pittacus_gossip_create(&self_addr, &net_receive_data, NULL);
  if (gossip == NULL)
  {
    LOG_ERROR("Gossip initialization failed: %s!", strerror(errno));
    return 1;
  }

  int join_result = pittacus_gossip_join(gossip, NULL, 0);
  if (join_result < 0)
  {
    LOG_ERROR("Gossip join failed: %d!", join_result);
    pittacus_gossip_destroy(gossip);
    return 1;
  }

  g_net_gossip = gossip;
  return 0;
}

int net_run_server(void)
{
  int is_seed_node = g_net_seed_mode || NUM_SEED_NODES == 0;
  if (is_seed_node)
  {
    if (net_open_connection())
    {
      LOG_ERROR("Failed to open seed node connection!");
      return 1;
    }
  }
  else
  {
    for (int i = 0; i < NUM_SEED_NODES; i++)
    {
      seed_node_entry_t seed_node_entry = SEED_NODES[i];
      if (net_connect(seed_node_entry.address, seed_node_entry.port))
      {
        LOG_ERROR("Failed to connect to seed with address: %s:%d!", seed_node_entry.address, seed_node_entry.port);
        return 1;
      }
      else
      {
        break;
      }
    }
  }

  pt_socket_fd gossip_fd = pittacus_gossip_socket_fd(g_net_gossip);
  struct pollfd gossip_poll_fd = {
    .fd = gossip_fd,
    .events = POLLIN,
    .revents = 0
  };

  int poll_interval = GOSSIP_TICK_INTERVAL;
  int recv_result = 0;
  int send_result = 0;
  int poll_result = 0;

  while (g_net_server_running)
  {
    gossip_poll_fd.revents = 0;
    poll_result = poll(&gossip_poll_fd, 1, poll_interval);
    if (poll_result > 0)
    {
      if (gossip_poll_fd.revents & POLLERR)
      {
        LOG_ERROR("Gossip socket failure: %s!", strerror(errno));
        pittacus_gossip_destroy(g_net_gossip);
        return 1;
      }
      else if (gossip_poll_fd.revents & POLLIN)
      {
        recv_result = pittacus_gossip_process_receive(g_net_gossip);
        if (recv_result < 0)
        {
          //LOG_DEBUG(stderr, "Gossip receive failed: %d!", recv_result);
          //pittacus_gossip_destroy(g_net_gossip);
          //return 1;
        }
      }
    }
    else if (poll_result < 0)
    {
      LOG_ERROR("Poll failed: %s!", strerror(errno));
      pittacus_gossip_destroy(g_net_gossip);
      return 1;
    }

    poll_interval = pittacus_gossip_tick(g_net_gossip);
    if (poll_interval < 0)
    {
      LOG_ERROR("Gossip tick failed: %d!", poll_interval);
      return 1;
    }

    send_result = pittacus_gossip_process_send(g_net_gossip);
    if (send_result < 0)
    {
      LOG_ERROR("Gossip send failed: %d, %s!", send_result, strerror(errno));
      pittacus_gossip_destroy(g_net_gossip);
      return 1;
    }

    // update the task manager
    taskmgr_tick();
  }

  pittacus_gossip_destroy(g_net_gossip);
  return 0;
}

int net_start_server(int seed_mode)
{
  if(g_net_server_running)
  {
    return 1;
  }

  mtx_init(&g_net_recv_mutex, mtx_plain);

  g_net_server_running = 1;
  g_net_seed_mode = seed_mode;

  g_net_resync_chain_task = add_task(resync_chain, RESYNC_CHAIN_TASK_DELAY);

  return net_run_server();
}

void net_stop_server(void)
{
  if(!g_net_server_running)
  {
    return;
  }

  mtx_destroy(&g_net_recv_mutex);
  g_net_server_running = 0;
}
