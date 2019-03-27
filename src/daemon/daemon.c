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

static const char *g_blockchain_data_dir = "blockchain";
static const char *g_wallet_filename = "wallet";
static const char *g_logger_log_filename = "daemon.log";
static int g_net_bind_port = P2P_PORT;
static const char *g_net_bind_address = "127.0.0.1:9899";

static int g_disable_port_mapping = 0;
static int g_enable_miner = 0;

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
    argument_t arg_type = argparse_get_argument_from_str(argv[i]);
    argument_map_t *argument_map = argparse_get_argument_map_from_type(arg_type);
    if (!argument_map)
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
        for (int i = 0; i < NUM_COMMANDS; i++)
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
        g_disable_port_mapping = 1;
        break;
      case CMD_ARG_BIND_ADDRESS:
        i++;
        //const char *bind_address = (const char*)argv[i];
        //net_set_bind_address(bind_address);
        break;
      case CMD_ARG_BIND_PORT:
        i++;
        const char *bind_port = (const char*)argv[i];
        char *address = "0.0.0.0";
        address = (char*)string_copy(address, ":");
        address = (char*)string_copy(address, bind_port);
        g_net_bind_port = atoi(bind_port);
        g_net_bind_address = address;
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

  if (g_disable_port_mapping == 0)
  {
    setup_net_port_mapping(g_net_bind_port);
  }

  init_net(g_net_bind_address);
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
