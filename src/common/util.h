// Copyright (c) 2019-2022, The Vulkan Developers.
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

#include "vulkan.h"

#include "crypto/cryptoutil.h"

VULKAN_BEGIN_DECL

VULKAN_API unsigned concatenate(unsigned x, unsigned y);

VULKAN_API uint16_t get_num_logical_cores(void);

VULKAN_API int string_equals(const char *string, const char *equals);
VULKAN_API int string_startswith(const char *string, const char *prefix);
VULKAN_API int string_endswith(const char *string, const char *ext);
VULKAN_API int string_count(const char *string, const char *countstr, int countbreak);
VULKAN_API const char* string_copy(const char *string, const char *other_string);

VULKAN_API int make_hash(char *digest, unsigned char *string);
VULKAN_API char* bin2hex(uint8_t *bin, size_t bin_size);
VULKAN_API uint8_t* hex2bin(const char *hexstr, size_t *size);

VULKAN_API uint32_t get_current_time(void);
VULKAN_API char* get_current_time_str(void);
VULKAN_API int cmp_least_greatest(const void *a, const void *b);

VULKAN_API int is_private_address(uint32_t ip);
VULKAN_API int is_local_address(uint32_t ip);
VULKAN_API uint32_t convert_str_to_ip(const char* address);
VULKAN_API char* convert_ip_to_str(uint32_t ip);
VULKAN_API char* convert_to_addr_str(const char* address, uint32_t port);

VULKAN_END_DECL
