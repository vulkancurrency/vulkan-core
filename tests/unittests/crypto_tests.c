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
#include <sodium.h>

#include "common/greatest.h"

#include "crypto/cryptoutil.h"
#include "crypto/sha256d.h"

SUITE(crypto_suite);

TEST can_hash_sha256d(void)
{
  const char *input = "Hello World!";
  uint8_t expected_output[] = {
    0x61, 0xf4, 0x17, 0x37,
    0x4f, 0x44, 0x00, 0xb4,
    0x7d, 0xca, 0xe1, 0xa8,
    0xf4, 0x02, 0xd4, 0xf4,
    0xda, 0xcf, 0x45, 0x5a,
    0x04, 0x42, 0xa0, 0x6a,
    0xa4, 0x55, 0xa4, 0x47,
    0xb0, 0xd4, 0xe1, 0x70
  };

  const char *input2 = "The quick brown fox jumps over the lazy dog";
  uint8_t expected_output2[] = {
    0x6d, 0x37, 0x79, 0x50,
    0x21, 0xe5, 0x44, 0xd8,
    0x2b, 0x41, 0x85, 0x0e,
    0xdf, 0x7a, 0xab, 0xab,
    0x9a, 0x0e, 0xbe, 0x27,
    0x4e, 0x54, 0xa5, 0x19,
    0x84, 0x0c, 0x46, 0x66,
    0xf3, 0x5b, 0x39, 0x37
  };

  const char *input3 = "THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890";
  uint8_t expected_output3[] = {
    0x2b, 0x71, 0xe6, 0x97,
    0x57, 0x91, 0x38, 0xf7,
    0xa5, 0x87, 0x6b, 0xaa,
    0x1c, 0xbb, 0x6b, 0x6d,
    0x51, 0x1c, 0xa2, 0xf7,
    0x80, 0x18, 0xcf, 0x99,
    0x72, 0x7c, 0xf7, 0xd4,
    0x44, 0xd9, 0x53, 0xcb
  };

  unsigned char output[crypto_hash_sha256_BYTES];
  crypto_hash_sha256d(output, (const unsigned char*)input, strlen(input));
  ASSERT_MEM_EQ(output, expected_output, crypto_hash_sha256_BYTES);

  unsigned char output2[crypto_hash_sha256_BYTES];
  crypto_hash_sha256d(output2, (const unsigned char*)input2, strlen(input2));
  ASSERT_MEM_EQ(output2, expected_output2, crypto_hash_sha256_BYTES);

  unsigned char output3[crypto_hash_sha256_BYTES];
  crypto_hash_sha256d(output3, (const unsigned char*)input3, strlen(input3));
  ASSERT_MEM_EQ(output3, expected_output3, crypto_hash_sha256_BYTES);

  PASS();
}

GREATEST_SUITE(crypto_suite)
{
  RUN_TEST(can_hash_sha256d);
}
