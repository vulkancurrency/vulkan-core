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

#include <stddef.h>
#include <stdint.h>

#include "pow.h"

#include "crypto/cryptoutil.h"

int check_pow(const uint8_t *hash, uint64_t difficulty)
{
  uint64_t low = 0, high = 0, top = 0, cur = 0;
  mul(swap64le(((const uint64_t*)hash)[3]), difficulty, &top, &high);
  if (high != 0)
  {
    return 0;
  }

  mul(swap64le(((const uint64_t*)hash)[0]), difficulty, &low, &cur);
  mul(swap64le(((const uint64_t*)hash)[1]), difficulty, &low, &high);
  int carry = cadd(cur, low);
  cur = high;
  mul(swap64le(((const uint64_t*)hash)[2]), difficulty, &low, &high);
  carry = cadc(cur, low, carry);
  carry = cadc(high, top, carry);
  return !carry;
}
