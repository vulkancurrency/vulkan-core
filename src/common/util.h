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

#include <stdlib.h>

#include <sodium.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define HASH_SIZE 32
#define ADDRESS_SIZE (crypto_hash_sha256_BYTES + 1)

#define RANDOM_RANGE(min, max) MAX(rand() % max, min)

uint16_t get_num_logical_cores(void);

int string_equals(const char *string, const char *equals);
int string_startswith(const char *string, const char *prefix);
int string_endswith(const char *string, const char *ext);
int string_count(const char *string, const char *countstr, int countbreak);
const char* string_copy(const char *string, const char *other_string);

int make_hash(char *digest, unsigned char *string);
uint32_t get_current_time(void);
int rmrf(const char *path);
void sort(void *base, size_t nitems, size_t size);

#ifdef __cplusplus
}
#endif
