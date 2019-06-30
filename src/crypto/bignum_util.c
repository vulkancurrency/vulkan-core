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

#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>

void bignum_set_compact(BIGNUM *bn, uint32_t n_compact)
{
  uint32_t n_size = n_compact >> 24;
  uint8_t vch[4 + n_size];
  memset(&vch, 0, sizeof(vch));
  vch[3] = n_size;
  if (n_size >= 1)
  {
    vch[4] = (n_compact >> 16) & 0xff;
  }

  if (n_size >= 2)
  {
    vch[5] = (n_compact >> 8) & 0xff;
  }

  if (n_size >= 3)
  {
    vch[6] = (n_compact >> 0) & 0xff;
  }

  BN_mpi2bn(&vch[0], sizeof(vch), bn);
}

uint32_t bignum_get_compact(BIGNUM *bn)
{
  uint32_t n_size = BN_bn2mpi(bn, NULL);
  uint8_t vch[n_size];
  memset(&vch, 0, sizeof(vch));
  n_size -= 4;
  BN_bn2mpi(bn, &vch[0]);
  uint32_t n_compact = n_size << 24;
  if (n_size >= 1)
  {
    n_compact |= (vch[4] << 16);
  }

  if (n_size >= 2)
  {
    n_compact |= (vch[5] << 8);
  }

  if (n_size >= 3)
  {
    n_compact |= (vch[6] << 0);
  }

  return n_compact;
}
