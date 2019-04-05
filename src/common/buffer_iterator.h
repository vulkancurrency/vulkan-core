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

#include "buffer.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct BufferIterator
{
  buffer_t *buffer;
  size_t offset;
} buffer_iterator_t;

buffer_iterator_t* buffer_iterator_init(buffer_t *buffer);
int buffer_iterator_free(buffer_iterator_t *buffer_iterator);

int buffer_iterator_set_buffer(buffer_iterator_t *buffer_iterator, buffer_t *buffer);
buffer_t *buffer_iterator_get_buffer(buffer_iterator_t *buffer_iterator);

int buffer_iterator_set_offset(buffer_iterator_t *buffer_iterator, size_t offset);
size_t buffer_iterator_get_offset(buffer_iterator_t *buffer_iterator);

int buffer_read(buffer_iterator_t *buffer_iterator, size_t size, uint8_t **bytes);
int buffer_get_remaining_size(buffer_iterator_t *buffer_iterator);
uint8_t* buffer_get_remaining_data(buffer_iterator_t *buffer_iterator);

int buffer_read_uint8(buffer_iterator_t *buffer_iterator, uint8_t *value);
int buffer_read_int8(buffer_iterator_t *buffer_iterator, int8_t *value);

int buffer_read_uint16(buffer_iterator_t *buffer_iterator, uint16_t *value);
int buffer_read_int16(buffer_iterator_t *buffer_iterator, int16_t *value);

int buffer_read_uint32(buffer_iterator_t *buffer_iterator, uint32_t *value);
int buffer_read_int32(buffer_iterator_t *buffer_iterator, int32_t *value);

uint64_t buffer_read_uint64(buffer_iterator_t *buffer_iterator, uint64_t *value);
int buffer_read_int64(buffer_iterator_t *buffer_iterator, int64_t *value);

int buffer_read_string(buffer_iterator_t *buffer_iterator, char **string);
int buffer_read_bytes(buffer_iterator_t *buffer_iterator, uint8_t **bytes);

#ifdef __cplusplus
}
#endif
