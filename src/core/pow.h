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

#include <stdint.h>

extern inline uint64_t hi_dword(uint64_t val);
extern inline uint64_t lo_dword(uint64_t val);

extern inline uint64_t mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t* product_hi);
extern inline void mul(uint64_t a, uint64_t b, uint64_t *low, uint64_t *high);

extern inline int cadd(uint64_t a, uint64_t b);
extern inline int cadc(uint64_t a, uint64_t b, int c);

extern inline uint32_t ident32(uint32_t x);
extern inline uint64_t ident64(uint64_t x);

#define swap32le ident32
#define swap64le ident64

int check_pow(const uint8_t *hash, uint64_t difficulty);
