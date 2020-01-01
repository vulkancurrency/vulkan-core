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
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "argparse.h"
#include "util.h"

int16_t argparse_get_argument_from_str(argument_map_t *arg_map, uint16_t num_args, const char *arg)
{
  assert(arg_map != NULL);
  for (int i = 0; i < num_args; i++)
  {
    argument_map_t *argument_map = &arg_map[i];
    assert(argument_map != NULL);

    if (string_endswith(arg, argument_map->name))
    {
      return argument_map->type;
    }
  }

  return CMD_ARG_UNKNOWN;
}

int16_t argparse_get_argument_with_prefix_from_str(argument_map_t *arg_map, uint16_t num_args, const char *arg)
{
  if (string_startswith(arg, "-") == 0 || string_count(arg, "-", 1) > 2)
  {
    return CMD_ARG_UNKNOWN;
  }

  return argparse_get_argument_from_str(arg_map, num_args, arg);
}

argument_map_t* argparse_get_argument_map_from_type(argument_map_t *arg_map, uint16_t num_args, int16_t arg_type)
{
  assert(arg_map != NULL);
  for (int i = 0; i < num_args; i++)
  {
    argument_map_t *argument_map = &arg_map[i];
    assert(argument_map != NULL);

    if (argument_map->type == arg_type)
    {
      return argument_map;
    }
  }

  return NULL;
}

char** argparse_parse_args_from_string(char *str, size_t *argc_out)
{
  char *tok;
  char *rest = str;

  size_t argc = 0;
  size_t argv_size = 0;
  char **argv = NULL;

  while ((tok = strtok_r(rest, " ", &rest)))
  {
    // strip space from line ending:
    size_t t_size = strlen(tok);
    if (t_size == 1 && isspace(tok[t_size - 1]))
    {
      break;
    }

    if (isspace(tok[t_size - 1]))
    {
      t_size--;
    }

    // copy the token str
    char *t = malloc(t_size);
    strncpy(t, tok, t_size);
    t[t_size] = '\0';

    // resize the argv array
    argv_size += strlen(tok);
    argv = (char**)realloc(argv, argv_size);

    argv[argc] = t;
    argc++;
  }

  *argc_out = argc;
  return argv;
}
