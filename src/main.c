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
#include <signal.h>
#include <string.h>

#include <sodium.h>

#include "argparse.h"
#include "chainparams.h"
#include "block.h"
#include "blockchain.h"
#include "miner.h"
#include "net.h"
#include "task.h"
#include "version.h"
#include "wallet.h"

static const char *g_blockchain_data_dir = "blockchain";
static const char *g_wallet_filename = "wallet";

static int g_enable_seed_mode = 0;
static int g_enable_miner = 0;

static void make_hash(char *digest, unsigned char *string)
{
  unsigned char hash[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(hash, string, strlen((char*)string));

  for (int i = 0; i < crypto_hash_sha256_BYTES; i++)
  {
    sprintf(&digest[i*2], "%02x", (unsigned int) hash[i]);
  }
}

static block_t* create_genesis_block(void)
{
  block_t *block = make_block();
  block->timestamp = genesis_block.timestamp;
  hash_block(block);

  int i = 0;
  while (!valid_block_hash(block))
  {
    block->nonce = i;
    hash_block(block);
    i++;
  }

  return block;
}

static void compare_genesis_block(block_t *block)
{
  if (compare_with_genesis_block(block) == 0)
  {
    printf("Verified genesis block!\n");
    print_block(block);
  }
  else
  {
    fprintf(stderr, "Genesis block mismatch, generated hash that is different than recorded!\n");
    print_block(block);
  }
}

static void perform_shutdown(int sig)
{
  close_blockchain();
  exit(1);
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
      case CMD_ARG_VERSION:
        printf("%s v%s-%s\n", APPLICATION_NAME, APPLICATION_VERSION, APPLICATION_RELEASE_NAME);
        return 1;
      case CMD_ARG_BIND_ADDRESS:
        i++;
        const char *bind_address = (const char*)argv[i];
        net_set_bind_address(bind_address);
        break;
      case CMD_ARG_BIND_PORT:
        i++;
        int bind_port = atoi(argv[i]);
        net_set_bind_port(bind_port);
        break;
      case CMD_ARG_DISABLE_PORT_MAPPING:
        net_set_disable_port_mapping(1);
        break;
      case CMD_ARG_BLOCKCHAIN_DIR:
        i++;
        g_blockchain_data_dir = (const char*)argv[i];
        break;
      case CMD_ARG_WALLET_FILENAME:
        i++;
        g_wallet_filename = (const char*)argv[i];
        break;
      case CMD_ARG_NEW_WALLET:
        i++;
        g_wallet_filename = (const char*)argv[i];
        new_wallet(g_wallet_filename);
        break;
      case CMD_ARG_CREATE_GENESIS_BLOCK:
        {
          block_t *block = create_genesis_block();
          printf("Generated new genesis block.\n");
          print_block(block);
        }
        return 1;
      case CMD_ARG_MINE:
        g_enable_miner = 1;
        break;
      case CMD_ARG_SEED_MODE:
        g_enable_seed_mode = 1;
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

  taskmgr_init();
  if (init_blockchain(g_blockchain_data_dir))
  {
    return 1;
  }

  if (g_enable_miner)
  {
    net_start_server(1, g_enable_seed_mode);
    start_mining();
  }
  else
  {
    net_start_server(0, g_enable_seed_mode);
  }

  if (close_blockchain())
  {
    return 1;
  }

  taskmgr_shutdown();
  return 0;
}
