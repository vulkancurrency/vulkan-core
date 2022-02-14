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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <assert.h>

#include <sodium.h>

#include "common/argparse.h"
#include "common/logger.h"
#include "common/task.h"

#include "core/block.h"
#include "core/blockchain.h"
#include "core/console.h"
#include "core/parameters.h"
#include "core/pow.h"
#include "core/mempool.h"
#include "core/net.h"
#include "core/p2p.h"
#include "core/protocol.h"
#include "core/version.h"

#include "miner/miner.h"

#include "wallet/wallet.h"

static connection_entries_t g_connection_entries;
static int g_enable_miner = 0;

static const char *g_blockchain_data_dir = "store-blockchain";
static const char *g_wallet_dir = "store-wallet";
static const char *g_logger_log_filename = "daemon.log";

static int g_repair_blockchain = 0;
static int g_repair_wallet = 0;

enum
{
  CMD_ARG_HELP = 0,
  CMD_ARG_VERSION,
  CMD_ARG_LOGGING_FILENAME,
  CMD_ARG_DISABLE_PORT_MAPPING,
  CMD_ARG_BIND_ADDRESS,
  CMD_ARG_BIND_PORT,
  CMD_ARG_CONNECT,
  CMD_ARG_BLOCKCHAIN_DIR,
  CMD_ARG_REPAIR_BLOCKCHAIN,
  CMD_ARG_CLEAR_BLOCKCHAIN,
  CMD_ARG_DISABLE_BLOCKCHAIN_COMPRESSION,
  CMD_ARG_BLOCKCHAIN_COMPRESSION_TYPE,
  CMD_ARG_P2P_STORAGE_FILENAME,
  CMD_ARG_WALLET_DIR,
  CMD_ARG_REPAIR_WALLET,
  CMD_ARG_CLEAR_WALLET,
  CMD_ARG_CREATE_GENESIS_BLOCK,
  CMD_ARG_FORCE_VERSION_CHECK,
  CMD_ARG_TESTNET,
  CMD_ARG_NUM_WORKER_THREADS,
  CMD_ARG_MINE
};

static const argument_map_t g_arguments_map[] = {
  {"help", CMD_ARG_HELP, "Shows the help information", "", 0},
  {"version", CMD_ARG_VERSION, "Shows the version information", "", 0},
  {"logging-filename", CMD_ARG_LOGGING_FILENAME, "Sets the logger output log filename", "<logger_filename>.log", 1},
  {"disable-port-mapping", CMD_ARG_DISABLE_PORT_MAPPING, "Disables UPnP port mapping", "", 0},
  {"bind-address", CMD_ARG_BIND_ADDRESS, "Sets the network bind address", "<bind_address>", 1},
  {"bind-port", CMD_ARG_BIND_PORT, "Sets the network bind port", "<bind_port>", 1},
  {"testnet", CMD_ARG_TESTNET, "Enable testnet mode which will only allow for custom testnet only parameters separate from the mainnet", "", 0},
  {"connect", CMD_ARG_CONNECT, "Attempts to connect to a manually specified peer", "<address:port>", 1},
  {"blockchain-dir", CMD_ARG_BLOCKCHAIN_DIR, "Change the blockchain database output directory", "<blockchain_dir>", 1},
  {"repair-blockchain", CMD_ARG_REPAIR_BLOCKCHAIN, "Repair the blockchain database directory in attempt to recover the data", "", 0},
  {"clear-blockchain", CMD_ARG_CLEAR_BLOCKCHAIN, "Clears the blockchain data on disk", "", 0},
  {"disable-blockchain-compression", CMD_ARG_DISABLE_BLOCKCHAIN_COMPRESSION, "Disables blockchain storage on disk compression", "", 0},
  {"blockchain-compression-type", CMD_ARG_BLOCKCHAIN_COMPRESSION_TYPE, "Sets the blockchain compression method to use", "<compression_method>", 1},
  {"p2p-storage-filename", CMD_ARG_P2P_STORAGE_FILENAME, "Sets the p2p peerlist storage database filename", "<db_storage_filename>", 1},
  {"wallet-dir", CMD_ARG_WALLET_DIR, "Change the wallet database output directory", "<wallet_dir>", 1},
  {"repair-wallet", CMD_ARG_REPAIR_WALLET, "Repair the wallet database directory in attempt to recover the data", "", 0},
  {"clear-wallet", CMD_ARG_CLEAR_WALLET, "Clears the wallet data on disk", "", 0},
  {"create-genesis-block", CMD_ARG_CREATE_GENESIS_BLOCK, "Creates and mine a new genesis block", "", 0},
  {"force-protocol-version-check", CMD_ARG_FORCE_VERSION_CHECK, "Forces protocol version check when accepting new incoming peer connections", "", 0},
  {"worker-threads", CMD_ARG_NUM_WORKER_THREADS, "Sets the number of miner worker threads to use when mining blocks", "<num_workers>", 1},
  {"mine", CMD_ARG_MINE, "Start mining for new blocks", "", 0}
};

#define NUM_ARGUMENTS (sizeof(g_arguments_map) / sizeof(argument_map_t))

static void perform_shutdown(int sig)
{
  if (g_enable_miner)
  {
    if (stop_mining())
    {
      exit(1);
      return;
    }
  }

  if (logger_close())
  {
    exit(1);
    return;
  }

  if (deinit_p2p())
  {
    exit(1);
    return;
  }

  if (stop_mempool())
  {
    exit(1);
    return;
  }

  if (close_blockchain())
  {
    exit(1);
    return;
  }

  if (deinit_net())
  {
    exit(1);
    return;
  }

  exit(0);
}

static int parse_commandline_args(int argc, char **argv)
{
  for (int i = 1; i < argc; i++)
  {
    int16_t arg_type = argparse_get_argument_with_prefix_from_str((argument_map_t*)&g_arguments_map, NUM_ARGUMENTS, argv[i]);
    argument_map_t *argument_map = argparse_get_argument_map_from_type((argument_map_t*)&g_arguments_map, NUM_ARGUMENTS, arg_type);
    if (argument_map == NULL)
    {
      fprintf(stderr, "Unknown command line argument: %s\n", argv[i]);
      return 1;
    }

    // check to see if the user provided the correct number of
    // arguments required by this option...
    int num_args = (argc - 1) - i;
    if (num_args < argument_map->num_args)
    {
      fprintf(stderr, "Usage: -%s, --%s: %s\n", argument_map->name, argument_map->name, argument_map->usage);
      return 1;
    }

    switch (arg_type)
    {
      case CMD_ARG_HELP:
        printf("%s v%s-%s\n", APPLICATION_NAME, APPLICATION_VERSION, APPLICATION_RELEASE_NAME);
        printf("\n");
        printf("Usage:\n");
        printf("  vulkan [command-line options]\n");
        printf("\n");
        printf("Command-line Options:\n");
        for (int i = 0; i < NUM_ARGUMENTS; i++)
        {
          argument_map_t *argument_map = &g_arguments_map[i];
          printf("  -%s, --%s: %s\n", argument_map->name, argument_map->name, argument_map->help);
        }

        printf("\n");
        return 1;
      case CMD_ARG_LOGGING_FILENAME:
        i++;
        g_logger_log_filename = (const char*)argv[i];
        break;
      case CMD_ARG_VERSION:
        printf("%s v%s-%s\n", APPLICATION_NAME, APPLICATION_VERSION, APPLICATION_RELEASE_NAME);
        return 1;
      case CMD_ARG_DISABLE_PORT_MAPPING:
        set_net_disable_port_mapping(1);
        break;
      case CMD_ARG_BIND_ADDRESS:
        i++;
        const char *host_address = (const char*)argv[i];
        set_net_host_address(host_address);
        break;
      case CMD_ARG_BIND_PORT:
        i++;
        uint16_t host_port = (uint16_t)atoi(argv[i]);
        set_net_host_port(host_port);
        break;
      case CMD_ARG_TESTNET:
        parameters_set_use_testnet(1);
        break;
      case CMD_ARG_CONNECT:
        {
          i++;
          const char *connect_address_str = (const char*)argv[i];
          char *token = strtok((char*)connect_address_str, ":");

          // get address
          char *address = malloc(strlen(token));
          memcpy(address, token, strlen(token));
          address[strlen(token)] = '\0';

          // get port
          token = strtok(NULL, ":");
          uint16_t port = (uint16_t)atoi(token);

          connection_entry_t connection_entry;
          connection_entry.address = address;
          connection_entry.port = port;

          assert(g_connection_entries.num_entries < NET_MAX_NUM_CONNECTION_ENTRIES);
          g_connection_entries.entries[g_connection_entries.num_entries] = connection_entry;
          g_connection_entries.num_entries++;
        }
        break;
      case CMD_ARG_BLOCKCHAIN_DIR:
        i++;
        g_blockchain_data_dir = (const char*)argv[i];
        break;
      case CMD_ARG_REPAIR_BLOCKCHAIN:
        g_repair_blockchain = 1;
        break;
      case CMD_ARG_CLEAR_BLOCKCHAIN:
        remove_blockchain(g_blockchain_data_dir);
        break;
      case CMD_ARG_DISABLE_BLOCKCHAIN_COMPRESSION:
        set_want_blockchain_compression(0);
        break;
      case CMD_ARG_BLOCKCHAIN_COMPRESSION_TYPE:
        i++;
        const char *compression_type_str = (const char*)argv[i];
        int compression_type = get_compression_type_from_str(compression_type_str);
        if (valid_compression_type(compression_type) == 0)
        {
          fprintf(stderr, "Unknown blockchain compression type: %s!\n", compression_type_str);
          return 1;
        }

        set_blockchain_compression_type(compression_type);
        break;
      case CMD_ARG_P2P_STORAGE_FILENAME:
        i++;
        const char *p2p_storage_filename = (const char*)argv[i];
        set_p2p_storage_filename(p2p_storage_filename);
      case CMD_ARG_WALLET_DIR:
        i++;
        g_wallet_dir = (const char*)argv[i];
        break;
      case CMD_ARG_REPAIR_WALLET:
        g_repair_wallet = 1;
        break;
      case CMD_ARG_CLEAR_WALLET:
        assert(remove_wallet(g_wallet_dir) == 0);
        break;
      case CMD_ARG_CREATE_GENESIS_BLOCK:
        {
          logger_set_log_filename(g_logger_log_filename);
          if (logger_open())
          {
            return 1;
          }

          taskmgr_init();
          set_miner_generate_genesis(1);
          wallet_t *wallet = NULL;

          // create a temporary wallet directory to store while we are
          // creating a new genesis block then delete it once we are finished:
          char* current_time_str = get_current_time_str();
          char* temp_wallet_dir = malloc(sizeof(char) * (strlen(g_wallet_dir) + 1 + strlen(current_time_str)));
          sprintf(temp_wallet_dir, "%s-%s", g_wallet_dir, current_time_str);
          free(current_time_str);

          if (init_wallet(temp_wallet_dir, &wallet))
          {
            return 1;
          }

          assert(wallet != NULL);
          set_current_wallet(wallet);
          if (start_mining())
          {
            return 1;
          }

          // now remove the wallet dir
          if (remove_wallet(temp_wallet_dir))
          {
            return 1;
          }

          free(temp_wallet_dir);
          if (logger_close())
          {
            return 1;
          }

          taskmgr_shutdown();
          return 0;
        }
        break;
      case CMD_ARG_FORCE_VERSION_CHECK:
        set_force_version_check(1);
        break;
      case CMD_ARG_NUM_WORKER_THREADS:
        i++;
        uint16_t num_worker_threads = (uint16_t)atoi(argv[i]);
        if (num_worker_threads < 1)
        {
          fprintf(stderr, "Must have at least one worker thread!\n");
          return 1;
        }

        set_num_worker_threads(num_worker_threads);
        break;
      case CMD_ARG_MINE:
        g_enable_miner = 1;
        break;
      default:
        fprintf(stderr, "Unknown command line argument: %s\n", argv[i]);
        return 1;
    }
  }

  return 0;
}

int main(int argc, char **argv)
{
  signal(SIGINT, perform_shutdown);
  if (sodium_init() == -1)
  {
    return 1;
  }

  if (init_pow())
  {
    return 1;
  }

  if (parse_commandline_args(argc, argv))
  {
    return 1;
  }

  logger_set_log_filename(g_logger_log_filename);
  if (logger_open())
  {
    return 1;
  }

  taskmgr_init();
  if (g_repair_blockchain)
  {
    assert(repair_blockchain(g_blockchain_data_dir) == 0);
  }

  if (start_mempool())
  {
    return 1;
  }

  if (init_blockchain(g_blockchain_data_dir, 1))
  {
    return 1;
  }

  if (init_p2p())
  {
    return 1;
  }

  if (init_net(g_connection_entries))
  {
    return 1;
  }

  wallet_t *wallet = NULL;
  if (g_enable_miner)
  {
    if (g_repair_wallet)
    {
      assert(repair_wallet(g_wallet_dir) == 0);
    }

    if (init_wallet(g_wallet_dir, &wallet))
    {
      return 1;
    }

    assert(wallet != NULL);
    set_current_wallet(wallet);
    if (start_mining())
    {
      return 1;
    }
  }

  if (init_console(wallet))
  {
    return 1;
  }

  if (net_run())
  {
    return 1;
  }

  if (deinit_console())
  {
    return 1;
  }

  if (wallet != NULL)
  {
    free_wallet(wallet);
  }

  if (deinit_p2p())
  {
    return 1;
  }

  if (stop_mempool())
  {
    return 1;
  }

  if (close_blockchain())
  {
    return 1;
  }

  taskmgr_shutdown();
  if (deinit_net())
  {
    return 1;
  }

  if (g_enable_miner)
  {
    if (stop_mining())
    {
      return 1;
    }
  }

  if (logger_close())
  {
    return 1;
  }

  if (deinit_pow())
  {
    return 1;
  }

  return 0;
}
