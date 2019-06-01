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
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#include <miniupnpc.h>
#include <upnpcommands.h>
#include <upnperrors.h>

#include "common/buffer_iterator.h"
#include "common/buffer.h"
#include "common/logger.h"
#include "common/mongoose.h"
#include "common/task.h"
#include "common/tinycthread.h"
#include "common/util.h"
#include "common/vec.h"

#include "checkpoints.h"
#include "net.h"
#include "p2p.h"
#include "parameters.h"
#include "protocol.h"
#include "seed_nodes.h"
#include "version.h"

static int g_net_initialized = 0;
static mtx_t g_net_lock;
static struct mg_mgr g_net_mgr;

static const char *g_net_host_address = "0.0.0.0";
static uint16_t g_net_host_port = P2P_PORT;
static const char *g_net_external_address = "";
static int g_net_disable_port_mapping = 0;

static task_t *g_net_resync_chain_task = NULL;
static task_t *g_net_reconnect_seeds_task = NULL;
static task_t *g_net_flush_connections_task = NULL;
static net_connection_t *g_net_connection = NULL;

static vec_void_t g_net_connections;
static int g_num_connections = 0;

void set_net_host_address(const char *host_address)
{
  g_net_host_address = host_address;
}

const char* get_net_host_address(void)
{
  return g_net_host_address;
}

void set_net_host_port(uint32_t host_port)
{
  g_net_host_port = host_port;
}

uint32_t get_net_host_port(void)
{
  return g_net_host_port;
}

const char* get_net_external_address(void)
{
  return g_net_external_address;
}

void set_net_disable_port_mapping(int disable_port_mapping)
{
  g_net_disable_port_mapping = disable_port_mapping;
}

int get_net_disable_port_mapping(void)
{
  return g_net_disable_port_mapping;
}

net_connection_t* init_net_connection(struct mg_connection *connection)
{
  assert(connection != NULL);
  net_connection_t *net_connection = malloc(sizeof(net_connection_t));
  net_connection->connection = connection;
  vec_init(&net_connection->send_queue);
  net_connection->send_queue_size = 0;

  net_connection->is_receiving_data = 0;
  net_connection->expected_receiving_len = 0;
  net_connection->receiving_buffer = NULL;

  net_connection->host_port = 0;
  net_connection->anonymous = 1;
  return net_connection;
}

void free_net_connection(net_connection_t *net_connection)
{
  assert(net_connection != NULL);
  vec_deinit(&net_connection->send_queue);
  if (net_connection->receiving_buffer != NULL)
  {
    buffer_free(net_connection->receiving_buffer);
    net_connection->receiving_buffer = NULL;
  }

  free(net_connection);
}

net_connection_t* get_net_connection_nolock(struct mg_connection *connection)
{
  assert(connection != NULL);
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
  assert(connection != NULL);
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

int close_net_connection(net_connection_t *net_connection)
{
  assert(net_connection != NULL);

  struct mg_connection *connection = net_connection->connection;
  assert(connection != NULL);

  connection->flags |= MG_F_CLOSE_IMMEDIATELY;
  return 0;
}

int broadcast_data(net_connection_t *net_connection, uint8_t *data, size_t data_len)
{
  assert(g_net_connection != NULL);
  return broadcast_data_to_peers(g_net_connection, data, data_len);
}

int send_data(net_connection_t *net_connection, uint8_t *data, size_t data_len)
{
  assert(net_connection != NULL);
  mtx_lock(&g_net_lock);
#ifdef USE_NET_QUEUE
  buffer_t *buffer = buffer_init_data(0, data, data_len);
  vec_push(&net_connection->send_queue, buffer);
  net_connection->send_queue_size++;
#else
  mg_send(net_connection->connection, data, data_len);
#endif
  mtx_unlock(&g_net_lock);
  return 0;
}

static int process_packet(net_connection_t *net_connection, buffer_iterator_t *buffer_iterator)
{
  assert(net_connection != NULL);
  assert(buffer_iterator != NULL);

  packet_t *packet = make_packet();
  if (deserialize_packet(packet, buffer_iterator))
  {
    LOG_DEBUG("Failed to deserialize incoming packet!");
    free_packet(packet);
    return 1;
  }

  if (handle_receive_packet(net_connection, packet))
  {
    LOG_DEBUG("Failed to handle incoming packet with id: %u!", packet->id);
    free_packet(packet);
    return 1;
  }

  free_packet(packet);
  return 0;
}

static void process_incoming_packet(net_connection_t *net_connection, buffer_iterator_t *buffer_iterator)
{
  assert(net_connection != NULL);
  assert(buffer_iterator != NULL);

  if (process_packet(net_connection, buffer_iterator))
  {
    //assert(close_net_connection(net_connection) == 0);
    return;
  }

  // check to see if we have any remaining data in the buffer,
  // sometimes data for several packets can be combined in attempt to
  // reduce overhead when trying to send multiple packets...
  size_t remaining_data_len = buffer_get_remaining_size(buffer_iterator);
  if (remaining_data_len > 0)
  {
    uint8_t *remaining_data = buffer_get_remaining_data(buffer_iterator);
    data_received(net_connection, remaining_data, remaining_data_len);
  }
}

void data_received(net_connection_t *net_connection, uint8_t *data, size_t data_len)
{
  assert(net_connection != NULL);
  assert(data != NULL);
  assert(data_len > 0);

  buffer_t *buffer = buffer_init_data(0, data, data_len);
  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);
  if (net_connection->is_receiving_data)
  {
    buffer_t *receiving_buffer = net_connection->receiving_buffer;
    assert(receiving_buffer != NULL);

    buffer_write(receiving_buffer, data, data_len);
    if (buffer_get_size(receiving_buffer) >= net_connection->expected_receiving_len)
    {
      buffer_iterator_t *buffer_iterator = buffer_iterator_init(receiving_buffer);
      process_incoming_packet(net_connection, buffer_iterator);
      buffer_iterator_free(buffer_iterator);

      net_connection->is_receiving_data = 0;
      net_connection->expected_receiving_len = 0;

      assert(net_connection->receiving_buffer != NULL);
      buffer_free(net_connection->receiving_buffer);
      net_connection->receiving_buffer = NULL;
    }
  }
  else
  {
    packet_t *packet = make_packet();
    if (deserialize_packet(packet, buffer_iterator))
    {
      assert(close_net_connection(net_connection) == 0);
    }
    else
    {
      if (data_len < packet->size)
      {
        net_connection->is_receiving_data = 1;
        net_connection->expected_receiving_len = packet->size;

        buffer_t *receiving_buffer = buffer_init_data(0, data, data_len);
        net_connection->receiving_buffer = receiving_buffer;
      }
      else
      {
        buffer_t *receiving_buffer = buffer_init_data(0, data, data_len);
        buffer_iterator_t *buffer_iterator = buffer_iterator_init(receiving_buffer);
        process_incoming_packet(net_connection, buffer_iterator);
        buffer_iterator_free(buffer_iterator);
        buffer_free(receiving_buffer);
      }
    }

    free_packet(packet);
  }

  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);
}

static void ev_handler(struct mg_connection *connection, int ev, void *p)
{
  assert(connection != NULL);
  struct mbuf *io = &connection->recv_mbuf;
  assert(io != NULL);
  switch (ev)
  {
    case MG_EV_ACCEPT:
      {
        net_connection_t *net_connection = init_net_connection(connection);
        assert(add_net_connection(net_connection) == 0);
      }
      break;
    case MG_EV_CONNECT:
      {
        net_connection_t *net_connection = get_net_connection(connection);
        assert(net_connection != NULL);
        assert(handle_packet_sendto(net_connection, PKT_TYPE_CONNECT_REQ, g_net_host_port) == 0);
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
          // check to see if we are trying to sync to the connection
          // that was just closed by the remote host...
          if (get_sync_initiated() && get_sync_net_connection() == net_connection)
          {
            uint32_t remote_ip = ntohl(*(uint32_t*)&connection->sa.sin.sin_addr);
            char *address_str = convert_ip_to_str(remote_ip);
            LOG_INFO("Connection closed during syncronization with peer %s:%u, continuing anyways...", address_str, net_connection->host_port);
            free(address_str);

            // forcefully end syncronization, since the connection we tried to sync to
            // has been closed, let's assume we have the top block so that we don't
            // restore the blockchain to the point before we started syncronizing...
            if (check_sync_status(1))
            {
              assert(clear_sync_request(0) == 0);
            }
          }

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

void setup_net_port_mapping(uint16_t port)
{
  LOG_INFO("Trying to add IGD port mapping...");
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

  // get our external pv4 address
  char *external_address = malloc(40);
  int external_ip_result = UPNP_GetExternalIPAddress(urls.controlURL, igdData.first.servicetype, external_address);
  g_net_external_address = (const char*)external_address;
  if (external_ip_result != UPNPCOMMAND_SUCCESS)
  {
    LOG_WARNING("Failed to get external IPV4 address!");
  }

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
    assert(taskmgr_tick() == 0);
  }

  return 0;
}

int connect_net_to_peer(const char *address, uint16_t port)
{
  char *bind_address = convert_to_addr_str(address, port);
  struct mg_connection *connection = mg_connect(&g_net_mgr, bind_address, ev_handler);
  if (connection == NULL)
  {
    LOG_WARNING("Failed to connect to peer with address: %s:%hu", bind_address, port);
    return 1;
  }

  free(bind_address);
  net_connection_t *net_connection = init_net_connection(connection);
  net_connection->host_port = port;
  assert(add_net_connection(net_connection) == 0);

  uint32_t remote_ip = ntohl(*(uint32_t*)&connection->sa.sin.sin_addr);
  uint64_t peer_id = concatenate(remote_ip, port);
  if (has_peer(peer_id))
  {
    LOG_DEBUG("Cannot add an already existant peer with id: %u!", peer_id);
    return 1;
  }

  peer_t *peer = init_peer(peer_id, net_connection);
  assert(add_peer(peer) == 0);
  return 0;
}

int connect_net_to_seeds(void)
{
  for (int i = 0; i < NUM_SEED_NODES; i++)
  {
    seed_node_entry_t seed_node_entry = SEED_NODES[i];
    uint32_t peer_ip = convert_str_to_ip(seed_node_entry.address);
    if (peer_ip == convert_str_to_ip(g_net_external_address) && seed_node_entry.port == g_net_host_port)
    {
      continue;
    }
    else if (peer_ip == convert_str_to_ip(g_net_host_address) && seed_node_entry.port == g_net_host_port)
    {
      continue;
    }
    else if (is_local_address(peer_ip) || is_private_address(peer_ip))
    {
      continue;
    }

    uint64_t peer_id = concatenate(peer_ip, seed_node_entry.port);
    if (has_peer(peer_id))
    {
      continue;
    }

    if (connect_net_to_peer(seed_node_entry.address, seed_node_entry.port))
    {
      continue;
    }
  }

  return 0;
}

int flush_send_queue(net_connection_t *net_connection)
{
  assert(net_connection != NULL);
  if (net_connection->send_queue_size > 0)
  {
    void *value = NULL;
    int index = 0;

    buffer_t *buffer = buffer_init();
    vec_foreach(&net_connection->send_queue, value, index)
    {
      buffer_t *queued_buffer = (buffer_t*)value;
      assert(queued_buffer != NULL);

      uint8_t *data = buffer_get_data(queued_buffer);
      size_t data_len = buffer_get_size(queued_buffer);

      buffer_write(buffer, data, data_len);
      buffer_free(queued_buffer);
    }

    vec_splice(&net_connection->send_queue, 0, net_connection->send_queue_size);
    net_connection->send_queue_size = 0;

    uint8_t *data = buffer_get_data(buffer);
    size_t data_len = buffer_get_size(buffer);

    mg_send(net_connection->connection, data, data_len);
    buffer_free(buffer);
  }

  return 0;
}

int flush_all_connections_nolock(void)
{
  void *value = NULL;
  int index = 0;
  vec_foreach(&g_net_connections, value, index)
  {
    net_connection_t *net_connection = (net_connection_t*)value;
    assert(net_connection != NULL);

    if (flush_send_queue(net_connection))
    {
      return 1;
    }
  }

  return 0;
}

int flush_all_connections(void)
{
  mtx_lock(&g_net_lock);
  int result = flush_all_connections_nolock();
  mtx_unlock(&g_net_lock);
  return result;
}

int flush_all_connections_noblock(void)
{
  if (mtx_trylock(&g_net_lock) == thrd_error)
  {
    return 0;
  }

  int result = flush_all_connections_nolock();
  mtx_unlock(&g_net_lock);
  return result;
}

task_result_t reconnect_seeds(task_t *task, va_list args)
{
  assert(task != NULL);
  assert(connect_net_to_seeds() == 0);
  return TASK_RESULT_WAIT;
}

task_result_t flush_connections(task_t *task, va_list args)
{
  assert(task != NULL);
  assert(flush_all_connections_noblock() == 0);
  return TASK_RESULT_WAIT;
}

int init_net(connection_entries_t connection_entries)
{
  if (g_net_initialized)
  {
    return 1;
  }

  vec_init(&g_net_connections);
  mtx_init(&g_net_lock, mtx_recursive);
  mg_mgr_init(&g_net_mgr, NULL);

  // setup port mapping
  if (g_net_disable_port_mapping == 0)
  {
    setup_net_port_mapping(g_net_host_port);
  }

  // setup the checkpoint data
  if (init_checkpoints())
  {
    return 1;
  }

  // setup the new connection
  char *bind_address = convert_to_addr_str(g_net_host_address, g_net_host_port);
  struct mg_connection *connection = mg_bind(&g_net_mgr, bind_address, ev_handler);
  if (connection == NULL)
  {
    LOG_ERROR("Failed to bind connection on address: %s!", bind_address);
    return 1;
  }

  free(bind_address);
  g_net_connection = init_net_connection(connection);
  g_net_connection->host_port = g_net_host_port;
  assert(add_net_connection(g_net_connection) == 0);

  // connect to the peers in the seeds list
  assert(connect_net_to_seeds() == 0);

  // connect to manually specified connection entries
  for (uint16_t i = 0; i < connection_entries.num_entries; i++)
  {
    connection_entry_t *connection_entry = &connection_entries.entries[i];
    assert(connection_entry != NULL);

    LOG_INFO("Attempting to connect to manually provided address: %s:%u...", connection_entry->address, connection_entry->port);
    if (connect_net_to_peer(connection_entry->address, connection_entry->port))
    {
      LOG_INFO("Failed to establish manual connection with %s:%u!", connection_entry->address, connection_entry->port);
    }

    free(connection_entry->address);
  }

  g_net_resync_chain_task = add_task(resync_chain, RESYNC_CHAIN_TASK_DELAY);
  g_net_reconnect_seeds_task = add_task(reconnect_seeds, NET_RECONNECT_SEEDS_TASK_DELAY);
#ifdef USE_NET_QUEUE
  g_net_flush_connections_task = add_task(flush_connections, NET_FLUSH_CONNECTIONS_TASK_DELAY);
#endif
  g_net_initialized = 1;
  return 0;
}

int deinit_net(void)
{
  if (g_net_initialized == 0)
  {
    return 1;
  }

  if (deinit_checkpoints())
  {
    return 1;
  }

  mg_mgr_free(&g_net_mgr);
  vec_deinit(&g_net_connections);
  remove_task(g_net_resync_chain_task);
  remove_task(g_net_reconnect_seeds_task);
#ifdef USE_NET_QUEUE
  remove_task(g_net_flush_connections_task);
#endif
  mtx_destroy(&g_net_lock);

  g_net_resync_chain_task = NULL;
  g_num_connections = 0;
  g_net_initialized = 0;
  return 0;
}
