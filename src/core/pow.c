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

#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/bn.h>

#include "common/util.h"

#include "pow.h"

#include "crypto/bignum_util.h"
#include "crypto/cryptoutil.h"

static const char *pow_limit_str = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

void get_pow_limit(BIGNUM *num)
{
  size_t out_size = 0;
  uint8_t *pow_limit_bin = hex2bin(pow_limit_str, &out_size);
  assert(out_size == HASH_SIZE);
  BN_bin2bn(pow_limit_bin, HASH_SIZE, num);
  free(pow_limit_bin);
}

int check_proof_of_work(const uint8_t *hash, uint32_t bits)
{
  BIGNUM bn_target;
  BN_init(&bn_target);
  bignum_set_compact(&bn_target, bits);

  BIGNUM pow_limit;
  BN_init(&pow_limit);
  get_pow_limit(&pow_limit);

  BIGNUM hash_target;
  BN_init(&hash_target);
  BN_bin2bn(hash, HASH_SIZE, &hash_target);

  // check range
  if (BN_is_zero(&bn_target) || BN_cmp(&bn_target, &pow_limit) == 1)
  {
    goto pow_check_fail;
  }

  // check proof of work
  if (BN_cmp(&hash_target, &bn_target) == 1)
  {
    goto pow_check_fail;
  }

  BN_clear_free(&bn_target);
  BN_clear_free(&pow_limit);
  BN_clear_free(&hash_target);
  return 1;

pow_check_fail:
  BN_clear_free(&bn_target);
  BN_clear_free(&pow_limit);
  BN_clear_free(&hash_target);
  return 0;
}
