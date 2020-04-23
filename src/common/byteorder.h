// Copyright (c) 2020, The Vulkan Developers.
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

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define PLATFORM_BIG_ENDIAN
#endif

#ifdef PLATFORM_BIG_ENDIAN

static inline uint16_t swap_le_16(uint16_t x)
{
  return (x & 0x00ff) << 8 |
         (x & 0xff00) >> 8;
}

static inline uint32_t swap_le_32(uint32_t x)
{
  return (x & 0x000000ff) << 24 |
         (x & 0x0000ff00) <<  8 |
         (x & 0x00ff0000) >>  8 |
         (x & 0xff000000) >> 24;
}

static inline uint64_t swap_le_64(uint64_t x)
{
  return (x & 0x00000000000000ff) << 56 |
         (x & 0x000000000000ff00) << 40 |
         (x & 0x0000000000ff0000) << 24 |
         (x & 0x00000000ff000000) <<  8 |
         (x & 0x000000ff00000000) >>  8 |
         (x & 0x0000ff0000000000) >> 24 |
         (x & 0x00ff000000000000) >> 40 |
         (x & 0xff00000000000000) >> 56;
}

#define swap_le(var) \
( \
  (sizeof(var) == 8) ? \
    swap_le_64(var) : \
  (sizeof(var) == 4) ? \
    swap_le_32(var) : \
  (sizeof(var) == 2) ? \
  swap_le_16(var) : \
  var \
)

#else
#define swap_le(var) (var)
#endif
