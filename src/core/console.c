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
#include <stdio.h>
#include <string.h>

#include "common/tinycthread.h"
#include "common/argparse.h"
#include "common/util.h"
#include "common/logger.h"

#include "console.h"
#include "net.h"

#include "wallet/wallet.h"

enum
{
  CMD_ARG_HELP = 0,
  CMD_ARG_PRINT_WALLET,
  CMD_ARG_CONNECT
};

static argument_map_t g_arguments_map[] = {
  {"help", CMD_ARG_HELP, "Shows the help information", "", 0},
  {"print_wallet", CMD_ARG_PRINT_WALLET, "Prints all of the details for the currently opened wallet", "", 0},
  {"connect", CMD_ARG_CONNECT, "Attempts to connect to a manually specified peer", "<address:port>", 1}
};

#define NUM_ARGUMENTS (sizeof(g_arguments_map) / sizeof(argument_map_t))

static int console_initialized = 0;
static thrd_t g_console_thread;
static wallet_t *g_current_wallet = NULL;

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
      LOG_ERROR("Bad usage of console argument: %s, expected usage: %s", argument_map->name, argument_map->usage);
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
      default:
        break;
    }
  }

  return 0;
}

static int console_mainloop()
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
}

int init_console(wallet_t *wallet)
{
  if (console_initialized)
  {
    return 1;
  }

  g_current_wallet = wallet;
  if (thrd_create(&g_console_thread, console_mainloop, NULL) != thrd_success)
  {
    LOG_ERROR("Failed to initialize console main thread!");
    return 1;
  }

  console_initialized = 1;
  return 0;
}

int deinit_console(void)
{
  if (!console_initialized)
  {
    return 1;
  }

  console_initialized = 0;
  return 0;
}
