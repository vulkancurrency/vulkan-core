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
#include <string.h>
#include <assert.h>

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#include "common/logger.h"
#include "common/mongoose.h"
#include "common/task.h"
#include "common/tinycthread.h"
#include "common/vec.h"

#include "parameters.h"
#include "net.h"
#include "p2p.h"
#include "protocol.h"
#include "version.h"

static int g_net_initialized = 0;
static mtx_t g_net_lock;
static struct mg_mgr g_net_mgr;

static task_t *g_net_resync_chain_task = NULL;
static net_connection_t *g_net_connection = NULL;

static vec_void_t g_net_connections;
static int g_num_connections;

net_connection_t* init_net_connection(struct mg_connection *connection)
{
  assert(connection != NULL);
  net_connection_t *net_connection = malloc(sizeof(net_connection_t));
  net_connection->connection = connection;
  net_connection->anonymous = 1;
  return net_connection;
}

int free_net_connection(net_connection_t *net_connection)
{
  assert(net_connection != NULL);
  free(net_connection);
  return 0;
}

net_connection_t* get_net_connection_nolock(struct mg_connection *connection)
{
  void *value = NULL;
  int index = 0;
  vec_foreach(&g_net_connections, value, index)
  {
    net_connection_t *net_connection = (net_connection_t*)value;
    assert(net_connection != NULL);

    if (net_connection->connection == connection)
    {
      return net_connection;
    }
  }

  return NULL;
}

net_connection_t* get_net_connection(struct mg_connection *connection)
{
  mtx_lock(&g_net_lock);
  net_connection_t *net_connection = get_net_connection_nolock(connection);
  mtx_unlock(&g_net_lock);
  return net_connection;
}

int has_net_connection_nolock(struct mg_connection *connection)
{
  return get_net_connection_nolock(connection) != NULL;
}

int has_net_connection(struct mg_connection *connection)
{
  mtx_lock(&g_net_lock);
  int result = has_net_connection_nolock(connection);
  mtx_unlock(&g_net_lock);
  return result;
}

int add_net_connection_nolock(net_connection_t *net_connection)
{
  assert(net_connection != NULL);
  if (has_net_connection(net_connection->connection))
  {
    return 1;
  }

  assert(vec_push(&g_net_connections, net_connection) == 0);
  g_num_connections++;
  return 0;
}

int add_net_connection(net_connection_t *net_connection)
{
  mtx_lock(&g_net_lock);
  int result = add_net_connection_nolock(net_connection);
  mtx_unlock(&g_net_lock);
  return result;
}

int remove_net_connection_nolock(net_connection_t *net_connection)
{
  assert(net_connection != NULL);
  if (has_net_connection(net_connection->connection) == 0)
  {
    return 1;
  }

  vec_remove(&g_net_connections, net_connection);
  g_num_connections--;
  return 0;
}

int remove_net_connection(net_connection_t *net_connection)
{
  mtx_lock(&g_net_lock);
  int result = remove_net_connection_nolock(net_connection);
  mtx_unlock(&g_net_lock);
  return result;
}

int broadcast_data(net_connection_t *net_connection, uint8_t *data, size_t data_len)
{
  assert(g_net_connection != NULL);
  return broadcast_data_to_peers(g_net_connection, data, data_len);
}

int send_data(net_connection_t *net_connection, uint8_t *data, size_t data_len)
{
  assert(net_connection != NULL);
  mg_send(net_connection->connection, data, data_len);
  return 0;
}

void data_received(net_connection_t *net_connection, uint8_t *data, size_t data_len)
{
  assert(net_connection != NULL);
  if (handle_receive_packet(net_connection, data, data_len))
  {
    LOG_DEBUG("Failed to handle incoming packet!");
  }
}

static void ev_handler(struct mg_connection *connection, int ev, void *p)
{
  struct mbuf *io = &connection->recv_mbuf;
  switch (ev)
  {
    case MG_EV_ACCEPT:
    case MG_EV_CONNECT:
      {
        net_connection_t *net_connection = init_net_connection(connection);
        assert(add_net_connection(net_connection) == 0);
        if (ev == MG_EV_CONNECT)
        {
          assert(handle_packet_sendto(net_connection, PKT_TYPE_CONNECT_REQ) == 0);
        }
      }
      break;
    case MG_EV_RECV:
      {
        net_connection_t *net_connection = get_net_connection(connection);
        assert(net_connection != NULL);
        data_received(net_connection, (uint8_t*)io->buf, io->len);
        mbuf_remove(io, io->len);
      }
      break;
    case MG_EV_CLOSE:
      {
        net_connection_t *net_connection = get_net_connection(connection);
        assert(net_connection != NULL);

        peer_t *peer = get_peer_from_net_connection(net_connection);
        if (peer != NULL)
        {
          assert(remove_peer(peer) == 0);
          free_peer(peer);
        }

        assert(remove_net_connection(net_connection) == 0);
        free_net_connection(net_connection);
      }
      break;
    default:
      break;
  }
}

void setup_net_port_mapping(int port)
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

      UPNP_DeletePortMapping(urls.controlURL, igdData.first.servicetype, port_string, "TCP", 0);
      int portMappingResult = UPNP_AddPortMapping(urls.controlURL, igdData.first.servicetype,
        port_string, port_string, lanAddress, APPLICATION_NAME, "TCP", 0, "0");

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

int net_run(void)
{
  while (g_net_initialized)
  {
    mg_mgr_poll(&g_net_mgr, NET_MGR_POLL_DELAY);
    taskmgr_tick();
  }

  return 0;
}

int init_net(const char *address)
{
  if (g_net_initialized)
  {
    return 1;
  }

  vec_init(&g_net_connections);
  mtx_init(&g_net_lock, mtx_recursive);
  mg_mgr_init(&g_net_mgr, NULL);

  // setup the new connection
  struct mg_connection *connection = mg_bind(&g_net_mgr, address, ev_handler);
  assert(connection != NULL);
  g_net_connection = init_net_connection(connection);
  assert(add_net_connection(g_net_connection) == 0);

  // connect to the peers in the peer list
  for (int i = 0; i < NUM_SEED_NODES; i++)
  {
    seed_node_entry_t seed_node_entry = SEED_NODES[i];
    if (strncmp(seed_node_entry.address, address, strlen(address)) == 0)
    {
      continue;
    }

    assert(mg_connect(&g_net_mgr, seed_node_entry.address, ev_handler) != NULL);
  }

  g_net_resync_chain_task = add_task(resync_chain, RESYNC_CHAIN_TASK_DELAY);
  g_net_initialized = 1;
  return net_run();
}

int deinit_net(void)
{
  if (g_net_initialized == 0)
  {
    return 1;
  }

  mg_mgr_free(&g_net_mgr);
  vec_deinit(&g_net_connections);
  remove_task(g_net_resync_chain_task);
  mtx_destroy(&g_net_lock);

  g_net_resync_chain_task = NULL;
  g_num_connections = 0;
  g_net_initialized = 0;
  return 0;
}
