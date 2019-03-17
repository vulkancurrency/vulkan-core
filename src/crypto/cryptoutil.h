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

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#include <sodium.h>

#define HASH_SIZE 32
#define ADDRESS_SIZE (crypto_hash_sha256_BYTES + 1)

static inline uint64_t hi_dword(uint64_t val)
{
  return val >> 32;
}

static inline uint64_t lo_dword(uint64_t val)
{
  return val & 0xFFFFFFFF;
}

static inline uint64_t mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t* product_hi)
{
  // multiplier   = ab = a * 2^32 + b
  // multiplicand = cd = c * 2^32 + d
  // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
  uint64_t a = hi_dword(multiplier);
  uint64_t b = lo_dword(multiplier);
  uint64_t c = hi_dword(multiplicand);
  uint64_t d = lo_dword(multiplicand);

  uint64_t ac = a * c;
  uint64_t ad = a * d;
  uint64_t bc = b * c;
  uint64_t bd = b * d;

  uint64_t adbc = ad + bc;
  uint64_t adbc_carry = adbc < ad ? 1 : 0;

  // multiplier * multiplicand = product_hi * 2^64 + product_lo
  uint64_t product_lo = bd + (adbc << 32);
  uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
  *product_hi = ac + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;
  assert(ac <= *product_hi);
  return product_lo;
}

#if defined(__x86_64__)
  static inline void mul(uint64_t a, uint64_t b, uint64_t *low, uint64_t *high)
  {
    *low = mul128(a, b, high);
  }
#else
  static inline void mul(uint64_t a, uint64_t b, uint64_t *low, uint64_t *high)
  {
    uint64_t aLow = a & 0xFFFFFFFF;
    uint64_t aHigh = a >> 32;
    uint64_t bLow = b & 0xFFFFFFFF;
    uint64_t bHigh = b >> 32;

    uint64_t res = aLow * bLow;
    uint64_t lowRes1 = res & 0xFFFFFFFF;
    uint64_t carry = res >> 32;

    res = aHigh * bLow + carry;
    uint64_t highResHigh1 = res >> 32;
    uint64_t highResLow1 = res & 0xFFFFFFFF;

    res = aLow * bHigh;
    uint64_t lowRes2 = res & 0xFFFFFFFF;
    carry = res >> 32;

    res = aHigh * bHigh + carry;
    uint64_t highResHigh2 = res >> 32;
    uint64_t highResLow2 = res & 0xFFFFFFFF;

    uint64_t r = highResLow1 + lowRes2;
    carry = r >> 32;
    *low = (r << 32) | lowRes1;
    r = highResHigh1 + highResLow2 + carry;
    uint64_t d3 = r & 0xFFFFFFFF;
    carry = r >> 32;
    r = highResHigh2 + carry;
    *high = d3 | (r << 32);
  }
#endif

static inline int cadd(uint64_t a, uint64_t b)
{
  return a + b < a;
}

static inline int cadc(uint64_t a, uint64_t b, int c)
{
  return a + b < a || (c && a + b == (uint64_t)-1);
}

static inline uint32_t ident32(uint32_t x)
{
  return x;
}

static inline uint64_t ident64(uint64_t x)
{
  return x;
}

#define swap32le ident32
#define swap64le ident64
