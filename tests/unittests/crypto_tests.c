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
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>

#include <sodium.h>

#include "common/greatest.h"
#include "common/util.h"

#include "crypto/bignum_util.h"
#include "crypto/cryptoutil.h"
#include "crypto/sha256d.h"

SUITE(crypto_suite);

TEST sha256_hash_tests(void)
{
  const char *input_str = "Hello World!";
  const char *expected_output_str = "61f417374f4400b47dcae1a8f402d4f4dacf455a0442a06aa455a447b0d4e170";

  size_t out_size = 0;
  uint8_t *expected_output = hex2bin(expected_output_str, &out_size);
  ASSERT(out_size == HASH_SIZE);

  const char *input2_str = "The quick brown fox jumps over the lazy dog";
  const char *expected_output2_str = "6d37795021e544d82b41850edf7aabab9a0ebe274e54a519840c4666f35b3937";

  uint8_t *expected_output2 = hex2bin(expected_output2_str, &out_size);
  ASSERT(out_size == HASH_SIZE);

  const char *input3_str = "THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890";
  const char *expected_output3_str = "2b71e697579138f7a5876baa1cbb6b6d511ca2f78018cf99727cf7d444d953cb";

  uint8_t *expected_output3 = hex2bin(expected_output3_str, &out_size);
  ASSERT(out_size == HASH_SIZE);

  unsigned char output[crypto_hash_sha256_BYTES];
  crypto_hash_sha256d(output, (const unsigned char*)input_str, strlen(input_str));
  ASSERT_MEM_EQ(output, expected_output, crypto_hash_sha256_BYTES);

  unsigned char output2[crypto_hash_sha256_BYTES];
  crypto_hash_sha256d(output2, (const unsigned char*)input2_str, strlen(input2_str));
  ASSERT_MEM_EQ(output2, expected_output2, crypto_hash_sha256_BYTES);

  unsigned char output3[crypto_hash_sha256_BYTES];
  crypto_hash_sha256d(output3, (const unsigned char*)input3_str, strlen(input3_str));
  ASSERT_MEM_EQ(output3, expected_output3, crypto_hash_sha256_BYTES);

  free(expected_output);
  free(expected_output2);
  free(expected_output3);

  PASS();
}

TEST bignum_compact_tests(void)
{
  BIGNUM *num = BN_new();
  bignum_set_compact(num, 0);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x00123456);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x01003456);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x02000056);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x03000000);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x04000000);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x00923456);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x01803456);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x02800056);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x03800000);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x04800000);
  ASSERT_EQ(bignum_get_compact(num), 0U);

  bignum_set_compact(num, 0x01123456);
  ASSERT_EQ(bignum_get_compact(num), 0x01120000U);

  bignum_set_compact(num, 0x01fedcba);
  ASSERT_EQ(bignum_get_compact(num), 0x01fe0000U);

  bignum_set_compact(num, 0x02123456);
  ASSERT_EQ(bignum_get_compact(num), 0x02123400U);

  bignum_set_compact(num, 0x03123456);
  ASSERT_EQ(bignum_get_compact(num), 0x03123456U);

  bignum_set_compact(num, 0x04123456);
  ASSERT_EQ(bignum_get_compact(num), 0x04123456U);

  bignum_set_compact(num, 0x04923456);
  ASSERT_EQ(bignum_get_compact(num), 0x04923456U);

  bignum_set_compact(num, 0x05009234);
  ASSERT_EQ(bignum_get_compact(num), 0x05009234U);

  bignum_set_compact(num, 0x20123456);
  ASSERT_EQ(bignum_get_compact(num), 0x20123456U);

  BN_clear_free(num);
  PASS();
}

GREATEST_SUITE(crypto_suite)
{
  RUN_TEST(sha256_hash_tests);
  RUN_TEST(bignum_compact_tests);
}
