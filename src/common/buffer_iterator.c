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
#include <assert.h>

#include "buffer_iterator.h"
#include "buffer.h"

buffer_iterator_t* buffer_iterator_init(buffer_t *buffer)
{
  assert(buffer != NULL);
  buffer_iterator_t *buffer_iterator = malloc(sizeof(buffer_iterator_t));
  buffer_iterator->buffer = buffer;
  buffer_iterator->offset = 0;
  return buffer_iterator;
}

int buffer_iterator_free(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  free(buffer_iterator);
  return 0;
}

uint8_t* buffer_read(buffer_iterator_t *buffer_iterator, size_t size)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint8_t *data = malloc(size);
  memcpy(data, buffer_iterator->buffer->data + buffer_iterator->offset, size);
  buffer_iterator->offset += size;
  return data;
}

int buffer_get_remaining_size(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  return buffer_iterator->buffer->size - buffer_iterator->offset;
}

const uint8_t* buffer_get_remaining_data(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  return buffer_iterator->buffer->data + buffer_iterator->offset;
}

uint8_t buffer_read_uint8(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint8_t value = *(uint8_t*)(buffer_iterator->buffer->data + buffer_iterator->offset);
  buffer_iterator->offset += 1;
  return value;
}

int8_t buffer_read_int8(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  int8_t value = *(int8_t*)(buffer_iterator->buffer->data + buffer_iterator->offset);
  buffer_iterator->offset += 1;
  return value;
}

uint16_t buffer_read_uint16(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint16_t value = *(uint16_t*)(buffer_iterator->buffer->data + buffer_iterator->offset);
  buffer_iterator->offset += 2;
  return value;
}

int16_t buffer_read_int16(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  int16_t value = *(int16_t*)(buffer_iterator->buffer->data + buffer_iterator->offset);
  buffer_iterator->offset += 2;
  return value;
}

uint32_t buffer_read_uint32(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint32_t value = *(uint32_t*)(buffer_iterator->buffer->data + buffer_iterator->offset);
  buffer_iterator->offset += 4;
  return value;
}

int32_t buffer_read_int32(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  int32_t value = *(int32_t*)(buffer_iterator->buffer->data + buffer_iterator->offset);
  buffer_iterator->offset += 4;
  return value;
}

uint64_t buffer_read_uint64(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint64_t value = *(uint64_t*)(buffer_iterator->buffer->data + buffer_iterator->offset);
  buffer_iterator->offset += 8;
  return value;
}

int64_t buffer_read_int64(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  int64_t value = *(int64_t*)(buffer_iterator->buffer->data + buffer_iterator->offset);
  buffer_iterator->offset += 8;
  return value;
}

char* buffer_read_string(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint32_t size = buffer_read_uint32(buffer_iterator);
  return (char*)buffer_read(buffer_iterator, size);
}

uint8_t* buffer_read_bytes(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint32_t size = buffer_read_uint32(buffer_iterator);
  return buffer_read(buffer_iterator, size);
}
