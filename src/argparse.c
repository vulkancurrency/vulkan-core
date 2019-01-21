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
#include <unistd.h>
#include <string.h>

#include "util.h"
#include "version.h"

#include "argparse.h"

argument_t argparse_get_argument_from_str(const char *arg)
{
  // verify command argument prefix
  if (!string_startswith(arg, "-") || string_count(arg, "-", 1) > 2)
  {
    return CMD_ARG_UNKNOWN;
  }

  // determine the argument type
  for (int i = 0; i < NUM_COMMANDS; i++)
  {
    argument_map_t *argument_map = &g_arguments_map[i];
    if (string_endswith(arg, argument_map->name))
    {
      return argument_map->type;
    }
  }
  return CMD_ARG_UNKNOWN;
}

argument_map_t* argparse_get_argument_map_from_type(argument_t arg_type)
{
  for (int i = 0; i < NUM_COMMANDS; i++)
  {
    argument_map_t *argument_map = &g_arguments_map[i];
    if (argument_map->type == arg_type)
    {
      return argument_map;
    }
  }
  return NULL;
}
