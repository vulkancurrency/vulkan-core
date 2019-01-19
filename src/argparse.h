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

#pragma once

typedef enum Argument
{
  CMD_ARG_HELP = 0,
  CMD_ARG_VERSION,

  CMD_ARG_BLOCKCHAIN_DIR,
  CMD_ARG_NEW_WALLET,
  CMD_ARG_MINE,
  CMD_ARG_SEED_MODE,

  CMD_ARG_UNKNOWN
} argument_t;

typedef struct ArgumentMap
{
  const char *name;
  argument_t type;
  const char *help;
  int num_args;
} argument_map_t;

static argument_map_t arguments_map[] = {
  {"help", CMD_ARG_HELP, "Shows the help information.", 0},
  {"version", CMD_ARG_VERSION, "Shows the version information.", 0},
  {"blockchain-dir", CMD_ARG_BLOCKCHAIN_DIR, "Change the blockchain database output directory.", 1},
  {"new-wallet", CMD_ARG_NEW_WALLET, "Create a new wallet file.", 1},
  {"mine", CMD_ARG_MINE, "Start mining for new blocks.", 0},
  {"seed-mode", CMD_ARG_SEED_MODE, "Run daemon in seed mode, do not connect to other peers.", 0}
};

#define NUM_COMMANDS (sizeof(arguments_map) / sizeof(argument_map_t))

argument_t argparse_get_argument_from_str(const char *arg);
argument_map_t* argparse_get_argument_map_from_type(argument_t arg_type);
int argparse_parse_args(int argc, char **argv);
