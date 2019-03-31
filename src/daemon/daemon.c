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
#include "core/parameters.h"
#include "core/mempool.h"
#include "core/net.h"
#include "core/p2p.h"
#include "core/version.h"

#include "miner/miner.h"

#include "wallet/wallet.h"

static int g_enable_miner = 0;

static const char *g_blockchain_data_dir = "blockchain";
static const char *g_wallet_filename = "wallet";
static const char *g_logger_log_filename = "daemon.log";

enum
{
  CMD_ARG_HELP = 0,
  CMD_ARG_VERSION,
  CMD_ARG_LOGGING_FILENAME,
  CMD_ARG_DISABLE_PORT_MAPPING,
  CMD_ARG_BIND_ADDRESS,
  CMD_ARG_BIND_PORT,
  CMD_ARG_BLOCKCHAIN_DIR,
  CMD_ARG_CLEAR_BLOCKCHAIN,
  CMD_ARG_WALLET_FILENAME,
  CMD_ARG_CLEAR_WALLET,
  CMD_ARG_CREATE_GENESIS_BLOCK,
  CMD_ARG_MINE
};

static argument_map_t g_arguments_map[] = {
  {"help", CMD_ARG_HELP, "Shows the help information.", "", 0},
  {"version", CMD_ARG_VERSION, "Shows the version information.", "", 0},
  {"logging-filename", CMD_ARG_LOGGING_FILENAME, "Sets the logger output log filename.", "<logger_filename>.log", 1},
  {"disable-port-mapping", CMD_ARG_DISABLE_PORT_MAPPING, "Disables UPnP port mapping.", "", 0},
  {"bind-address", CMD_ARG_BIND_ADDRESS, "Sets the network bind address.", "<bind_address>", 1},
  {"bind-port", CMD_ARG_BIND_PORT, "Sets the network bind port.", "<bind_port>", 1},
  {"blockchain-dir", CMD_ARG_BLOCKCHAIN_DIR, "Change the blockchain database output directory.", "<blockchain_dir>", 1},
  {"clear-blockchain", CMD_ARG_CLEAR_BLOCKCHAIN, "Clears the blockchain data on disk.", "", 0},
  {"wallet-filename", CMD_ARG_WALLET_FILENAME, "Change the wallet database output filename.", "<wallet_filename>", 1},
  {"clear-wallet", CMD_ARG_CLEAR_WALLET, "Clears the wallet data on disk.", "", 0},
  {"create-genesis-block", CMD_ARG_CREATE_GENESIS_BLOCK, "Creates and mine a new genesis block.", "", 0},
  {"mine", CMD_ARG_MINE, "Start mining for new blocks.", "<num_worker_threads>", 1}
};

#define NUM_ARGUMENTS (sizeof(g_arguments_map) / sizeof(argument_map_t))

static void perform_shutdown(int sig)
{
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
    uint16_t arg_type = argparse_get_argument_from_str((argument_map_t*)&g_arguments_map, NUM_ARGUMENTS, argv[i]);
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
        uint32_t host_port = atoi(argv[i]);
        set_net_host_port(host_port);
        break;
      case CMD_ARG_BLOCKCHAIN_DIR:
        i++;
        g_blockchain_data_dir = (const char*)argv[i];
        break;
      case CMD_ARG_CLEAR_BLOCKCHAIN:
        remove_blockchain(g_blockchain_data_dir);
        break;
      case CMD_ARG_WALLET_FILENAME:
        i++;
        g_wallet_filename = (const char*)argv[i];
        break;
      case CMD_ARG_CLEAR_WALLET:
        rmrf(g_wallet_filename);
        break;
      case CMD_ARG_CREATE_GENESIS_BLOCK:
        {
          wallet_t *wallet = init_wallet(g_wallet_filename);
          assert(wallet != NULL);

          block_t *block = compute_genesis_block(wallet);
          assert(block != NULL);

          printf("Generated new genesis block.\n");
          print_block(block);
          printf("\n");
          print_block_transactions(block);

          free_block(block);
          free_wallet(wallet);
        }
        return 1;
      case CMD_ARG_MINE:
        i++;
        size_t num_worker_threads = atoi(argv[i]);
        if (num_worker_threads < 1)
        {
          fprintf(stderr, "Invalid number of worker threads: %zu!\n", num_worker_threads);
          return 1;
        }

        g_enable_miner = 1;
        set_num_worker_threads(num_worker_threads);
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
  if (parse_commandline_args(argc, argv))
  {
    return 1;
  }

  logger_set_log_filename(g_logger_log_filename);
  if (logger_open())
  {
    return 1;
  }

  if (sodium_init() == -1)
  {
    return 1;
  }

  taskmgr_init();
  if (init_blockchain(g_blockchain_data_dir))
  {
    return 1;
  }

  if (start_mempool())
  {
    return 1;
  }

  if (init_p2p())
  {
    return 1;
  }

  wallet_t *wallet = NULL;
  if (g_enable_miner)
  {
    wallet = init_wallet(g_wallet_filename);
    assert(wallet != NULL);

    set_current_wallet(wallet);
    start_mining();
  }

  if (init_net())
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

  return 0;
}
