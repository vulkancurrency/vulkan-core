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
//
// Parts of this file are originally copyright (c) 2012-2013, The CryptoNote Developers.

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#include "common/util.h"
#include "common/vec.h"

#include "parameters.h"
#include "difficulty.h"
#include "pow.h"

uint64_t get_next_difficulty(difficulty_info_t difficulty_info)
{
  size_t length = difficulty_info.num_timestamps;
  assert(length == difficulty_info.num_cumulative_difficulties);
  if (length <= 1)
  {
    return 1;
  }

  assert(DIFFICULTY_WINDOW >= 2);
  assert(length <= DIFFICULTY_WINDOW);
  vec_sort(&difficulty_info.timestamps, sort_compare);
  size_t cut_begin = 0, cut_end = 0;
  assert(2 * DIFFICULTY_CUT <= DIFFICULTY_WINDOW - 2);
  if (length <= DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT)
  {
    cut_begin = 0;
    cut_end = length;
  }
  else
  {
    cut_begin = (length - (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT) + 1) / 2;
    cut_end = cut_begin + (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT);
  }

  assert(cut_begin + 2 <= cut_end && cut_end <= length);
  uint32_t timespan = (uint32_t)vec_get(&difficulty_info.timestamps, cut_end - 1) - (uint32_t)vec_get(&difficulty_info.timestamps, cut_begin);
  if (timespan == 0)
  {
    timespan = 1;
  }

  uint64_t total_work = (uint64_t)vec_get(&difficulty_info.cumulative_difficulties, cut_end - 1) - (uint32_t)vec_get(&difficulty_info.cumulative_difficulties, cut_begin);
  assert(total_work > 0);
  uint64_t low = 0, high = 0;
  mul(total_work, difficulty_info.target_seconds, &low, &high);
  if (high != 0 || low + timespan - 1 < low)
  {
    return 0;
  }

  return (low + timespan - 1) / timespan;
}
