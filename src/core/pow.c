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

#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/bn.h>

#include "common/util.h"

#include "pow.h"

#include "crypto/bignum_util.h"
#include "crypto/cryptoutil.h"

static const char *g_pow_limit_str = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
BIGNUM *g_pow_limit_bn = NULL;

int init_pow(void)
{
  if (g_pow_limit_bn != NULL)
  {
    return 1;
  }

  size_t out_size = 0;
  uint8_t *pow_limit_bin = hex2bin(g_pow_limit_str, &out_size);
  assert(out_size == HASH_SIZE);

  g_pow_limit_bn = BN_new();
  BN_bin2bn(pow_limit_bin, HASH_SIZE, g_pow_limit_bn);
  assert(!BN_is_zero(g_pow_limit_bn));
  free(pow_limit_bin);
  return 0;
}

int deinit_pow(void)
{
  if (g_pow_limit_bn == NULL)
  {
    return 1;
  }

  BN_clear_free(g_pow_limit_bn);
  g_pow_limit_bn = NULL;
  return 0;
}

int check_proof_of_work(const uint8_t *hash, uint32_t bits)
{
  assert(!BN_is_zero(g_pow_limit_bn));

  BIGNUM *bn_target = BN_new();
  bignum_set_compact(bn_target, bits);

  BIGNUM *hash_target = BN_new();
  BN_bin2bn(hash, HASH_SIZE, hash_target);

  // check range
  if (BN_is_zero(bn_target) || BN_cmp(bn_target, g_pow_limit_bn) == 1)
  {
    goto pow_check_fail;
  }

  // check proof of work
  if (BN_cmp(hash_target, bn_target) == 1)
  {
    goto pow_check_fail;
  }

  BN_clear_free(bn_target);
  BN_clear_free(hash_target);
  return 1;

pow_check_fail:
  BN_clear_free(bn_target);
  BN_clear_free(hash_target);
  return 0;
}
