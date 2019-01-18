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

#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <getopt.h>
#include <string.h>
#include <sodium.h>

#include "chainparams.h"
#include "version.h"
#include "block.h"
#include "wallet.h"
#include "net.h"
#include "chain.h"
#include "miner.h"
#include "client.h"

#include "argparse.h"

static const char *blockchain_data_dir = "blockchain";
static int enable_miner = 0;

void make_hash(char *digest, unsigned char *string)
{
  unsigned char hash[crypto_hash_sha256_BYTES];

  crypto_hash_sha256(hash, string, strlen((char *) string));

  for (int i = 0; i < crypto_hash_sha256_BYTES; i++)
  {
    sprintf(&digest[i*2], "%02x", (unsigned int) hash[i]);
  }
}

void perform_shutdown(int sig)
{
  close_blockchain();
  exit(1);
}

int parse_commandline_args(int argc, char **argv)
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
      fprintf(stderr, "Usage: -%s, --%s: %s\n", argument_map->name, argument_map->name, argument_map->help);
      return 1;
    }
    switch (arg_type)
    {
      case CMD_ARG_HELP:
        fprintf(stderr, "Command-line Options:\n");
        for (int i = 0; i < NUM_COMMANDS; i++)
        {
          argument_map_t *argument_map = &arguments_map[i];
          fprintf(stderr, "  -%s, --%s: %s\n", argument_map->name, argument_map->name, argument_map->help);
        }
        fprintf(stderr, "\n");
        return 1;
      case CMD_ARG_VERSION:
        printf("%s v%s-%s\n", APPLICATION_NAME, APPLICATION_VERSION, APPLICATION_RELEASE_NAME);
        return 1;
      case CMD_ARG_BLOCKCHAIN_DIR:
        i++;
        blockchain_data_dir = (const char*)argv[i];
        break;
      case CMD_ARG_NEW_WALLET:
        new_wallet();
        break;
      case CMD_ARG_MINE:
        enable_miner = 1;
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
  if (sodium_init() == -1)
  {
    return 1;
  }

  signal(SIGINT, perform_shutdown);
  if (parse_commandline_args(argc, argv))
  {
    return 1;
  }

  init_blockchain(blockchain_data_dir);
  if (enable_miner)
  {
    net_start_server(1);
    start_mining();
  }
  else
  {
    net_start_server(0);
  }

  close_blockchain();
  return 0;
}
