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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "common/tinycthread.h"
#include "common/argparse.h"
#include "common/util.h"
#include "common/logger.h"

#include "block.h"
#include "blockchain.h"
#include "console.h"
#include "mempool.h"
#include "net.h"
#include "p2p.h"
#include "parameters.h"
#include "transaction_builder.h"

#include "miner/miner.h"

#include "wallet/wallet.h"

enum
{
  CMD_ARG_HELP = 0,
  CMD_ARG_PRINT_BC,
  CMD_ARG_PRINT_WALLET,
  CMD_ARG_HEIGHT,
  CMD_ARG_CONNECT,
  CMD_ARG_START_MINING,
  CMD_ARG_STOP_MINING,
  CMD_ARG_XFER,
  CMD_ARG_PRINT_PEERLIST
};

static argument_map_t g_arguments_map[] = {
  {"help", CMD_ARG_HELP, "Shows the help information", "", 0},
  {"print_bc", CMD_ARG_PRINT_BC, "Prints all blocks from start height to end height", "<start_height, end_height>", 2},
  {"print_wallet", CMD_ARG_PRINT_WALLET, "Prints all of the details for the currently opened wallet", "", 0},
  {"height", CMD_ARG_HEIGHT, "Prints the current blockchain top block height", "", 0},
  {"connect", CMD_ARG_CONNECT, "Attempts to connect to a manually specified peer", "<address:port>", 1},
  {"start_mining", CMD_ARG_START_MINING, "Resumes all mining threads", "", 0},
  {"stop_mining", CMD_ARG_STOP_MINING, "Pauses all mining threads", "", 0},
  {"xfer", CMD_ARG_XFER, "Xfer money to another wallet from the currently opened wallet", "<address, amount>", 2},
  {"print_pl", CMD_ARG_PRINT_PEERLIST, "Prints all of our connected peers in the peerlist", "", 0}
};

#define NUM_ARGUMENTS (sizeof(g_arguments_map) / sizeof(argument_map_t))

static int console_initialized = 0;
static thrd_t g_console_thread;
static wallet_t *g_current_wallet = NULL;

static task_t *g_console_loop_task = NULL;

static char *_line = NULL;
static size_t _len = 0;
static ssize_t _read = -1;

static int parse_console_args(int argc, char **argv)
{
  for (int i = 0; i < argc; i++)
  {
    int16_t arg_type = argparse_get_argument_from_str((argument_map_t*)&g_arguments_map, NUM_ARGUMENTS, argv[i]);
    argument_map_t *argument_map = argparse_get_argument_map_from_type((argument_map_t*)&g_arguments_map, NUM_ARGUMENTS, arg_type);
    if (argument_map == NULL)
    {
      LOG_ERROR("Unknown console argument: %s", argv[i]);
      return 1;
    }

    // check to see if the user provided the correct number of
    // arguments required by this option...
    int num_args = (argc - 1) - i;
    if (num_args < argument_map->num_args)
    {
      LOG_ERROR("Bad usage of console command: %s, expected usage: %s", argument_map->name, argument_map->usage);
      return 1;
    }

    switch (arg_type)
    {
      case CMD_ARG_HELP:
        printf("\n");
        printf("Console Commands:\n");
        for (int i = 0; i < NUM_ARGUMENTS; i++)
        {
          argument_map_t *argument_map = &g_arguments_map[i];
          printf("  %s: %s\n", argument_map->name, argument_map->help);
        }

        printf("\n");
        return 1;
      case CMD_ARG_PRINT_BC:
        {
          i++;
          uint32_t start_height = (uint32_t)atol(argv[i]);
          i++;
          uint32_t end_height = (uint32_t)atol(argv[i]);
          uint32_t current_block_height = get_block_height();

          start_height = MIN(start_height, current_block_height);
          end_height = MIN(end_height, current_block_height);
          if (start_height == end_height)
          {
            return 1;
          }

          LOG_INFO("Printing blocks...");
          for (uint32_t i = start_height; i <= end_height; i++)
          {
            LOG_INFO("Printing block at height: %llu", i);
            block_t *block = get_block_from_height(i);
            print_block(block);
            print_block_transactions(block);
          }

          printf("\n");
        }
        break;
      case CMD_ARG_HEIGHT:
        {
          uint32_t current_block_height = get_block_height();
          LOG_INFO("Current blockchain top block height: %llu", current_block_height);
        }
        break;
      case CMD_ARG_PRINT_WALLET:
        {
          if (g_current_wallet == NULL)
          {
            LOG_ERROR("Cannot print wallet details, no wallet was opened!");
            return 1;
          }

          print_wallet(g_current_wallet);
        }
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

          LOG_INFO("Attempting to connect to manually provided address: %s:%u...", address, port);
          if (connect_net_to_peer(address, port))
          {
            LOG_INFO("Failed to establish manual connection with %s:%u!", address, port);
          }
        }
        break;
      case CMD_ARG_START_MINING:
        set_workers_paused(false);
        break;
      case CMD_ARG_STOP_MINING:
        set_workers_paused(true);
        break;
      case CMD_ARG_XFER:
        {
          i++;
          char *address_str = (char*)argv[i];
          i++;
          uint64_t amount = (uint64_t)atol(argv[i]) * COIN;

          size_t address_size = 0;
          uint8_t *address = hex2bin(address_str, &address_size);
          assert(address_size == ADDRESS_SIZE);

          transaction_entry_t tx_entry;
          memcpy(tx_entry.address, address, ADDRESS_SIZE);
          tx_entry.amount = amount;

          free(address);

          transaction_entries_t tx_entries;
          tx_entries.num_entries++;
          tx_entries.entries[tx_entries.num_entries - 1] = &tx_entry;

          transaction_t *tx = NULL;
          int r = construct_spend_tx(&tx, g_current_wallet, 1, tx_entries);
          assert(!r);
          r = validate_and_add_tx_to_mempool(tx);
          assert(!r);
        }
        break;
      case CMD_ARG_PRINT_PEERLIST:
        print_p2p_list();
        break;
      default:
        break;
    }
  }

  return 0;
}

/*static int console_mainloop()
{
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  while (console_initialized)
  {
    while ((read = getline(&line, &len, stdin)) != -1)
    {
      // pull all args from the line delimited by spaces:
      size_t argc = 0;
      char **argv = argparse_parse_args_from_string(line, &argc);

      // parse the arguments:
      if (parse_console_args(argc, argv))
      {
        continue;
      }
    }

    free(line);
  }

  return 0;
}*/

task_result_t console_loop(task_t *task, va_list args)
{
  if ((_read = getline(&_line, &_len, stdin)) != -1)
  {
    // pull all args from the line delimited by spaces:
    size_t argc = 0;
    char **argv = argparse_parse_args_from_string(_line, &argc);

    // parse the arguments:
    if (parse_console_args(argc, argv))
    {

    }
  }

  if (_read > 0)
  {
    free(_line);
    _line = NULL;
  }

  return TASK_RESULT_WAIT;
}

int init_console(wallet_t *wallet)
{
  if (console_initialized)
  {
    return 1;
  }

  g_current_wallet = wallet;
  /*if (thrd_create(&g_console_thread, console_mainloop, NULL) != thrd_success)
  {
    LOG_ERROR("Failed to initialize console main thread!");
    return 1;
  }*/

  g_console_loop_task = add_task(console_loop, 0.05);

  console_initialized = 1;
  return 0;
}

int deinit_console(void)
{
  if (!console_initialized)
  {
    return 1;
  }

  remove_task(g_console_loop_task);
  console_initialized = 0;
  return 0;
}
