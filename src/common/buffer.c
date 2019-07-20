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
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "buffer.h"

buffer_t* buffer_init_data(size_t offset, const uint8_t *data, size_t size)
{
  buffer_t *buffer = malloc(sizeof(buffer_t));
  if (buffer == NULL)
  {
    return NULL;
  }

  buffer->data = NULL;
  if (size > 0)
  {
    buffer->data = malloc(size);
    if (buffer->data == NULL)
    {
      return NULL;
    }

    if (data != NULL)
    {
      memcpy(buffer->data, data, size);
    }
    else
    {
      memset(buffer->data, 0, size);
    }
  }

  buffer->size = size;
  buffer->offset = offset;
  return buffer;
}

buffer_t* buffer_init_size(size_t offset, size_t size)
{
  const uint8_t *data = NULL;
  return buffer_init_data(offset, data, size);
}

buffer_t* buffer_init_offset(size_t offset)
{
  return buffer_init_size(offset, 0);
}

buffer_t* buffer_init(void)
{
  return buffer_init_offset(0);
}

void buffer_set_data(buffer_t *buffer, const uint8_t *data, size_t size)
{
  assert(buffer != NULL);
  assert(data != NULL);
  assert(size > 0);
  memcpy(buffer->data, data, size);
  buffer->size = size;
  buffer->offset = 0;
}

uint8_t* buffer_get_data(buffer_t *buffer)
{
  assert(buffer != NULL);
  return buffer->data;
}

void buffer_set_size(buffer_t *buffer, size_t size)
{
  assert(buffer != NULL);
  buffer->size = size;
}

size_t buffer_get_size(buffer_t *buffer)
{
  assert(buffer != NULL);
  return buffer->size;
}

void buffer_set_offset(buffer_t *buffer, size_t offset)
{
  assert(buffer != NULL);
  buffer->offset = offset;
}

size_t buffer_get_offset(buffer_t *buffer)
{
  assert(buffer != NULL);
  return buffer->offset;
}

int buffer_copy(buffer_t *buffer, buffer_t *other_buffer)
{
  assert(buffer != NULL);
  assert(other_buffer != NULL);
  buffer_clear(buffer);
  assert(buffer_realloc(buffer, other_buffer->size) == 0);
  memcpy(buffer->data, other_buffer->data, other_buffer->size);
  buffer->size = other_buffer->size;
  buffer->offset = other_buffer->offset;
  return 0;
}

int buffer_compare(buffer_t *buffer, buffer_t *other_buffer)
{
  assert(buffer != NULL);
  assert(other_buffer != NULL);
  return (
    memcmp(buffer->data, other_buffer->data, buffer->size) == 0 &&
    buffer->size == other_buffer->size &&
    buffer->offset == other_buffer->offset);
}

void buffer_clear(buffer_t *buffer)
{
  assert(buffer != NULL);
  if (buffer->data != NULL)
  {
    free(buffer->data);
    buffer->data = NULL;
  }

  buffer->size = 0;
  buffer->offset = 0;
}

void buffer_free(buffer_t *buffer)
{
  assert(buffer != NULL);
  if (buffer->data != NULL)
  {
    free(buffer->data);
    buffer->data = NULL;
  }

  buffer->size = 0;
  buffer->offset = 0;
  free(buffer);
}

int buffer_realloc(buffer_t *buffer, size_t size)
{
  assert(buffer != NULL);
  assert(size > 0);
  size_t current_size = buffer->size - buffer->offset;
  if (current_size >= size)
  {
    return 1;
  }

  buffer->data = realloc(buffer->data, buffer->size + size);
  assert(buffer->data != NULL);
  buffer->size += size;
  return 0;
}

int buffer_write(buffer_t *buffer, const uint8_t *data, size_t size)
{
  assert(buffer != NULL);
  assert(size > 0);
  buffer_realloc(buffer, size);
  memcpy(buffer->data + buffer->offset, data, size);
  buffer->offset += size;
  return 0;
}

int buffer_write_uint8(buffer_t *buffer, uint8_t value)
{
  assert(buffer != NULL);
  buffer_realloc(buffer, 1);
  *(uint8_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 1;
  return 0;
}

int buffer_write_int8(buffer_t *buffer, int8_t value)
{
  assert(buffer != NULL);
  buffer_realloc(buffer, 1);
  *(int8_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 1;
  return 0;
}

int buffer_write_uint16(buffer_t *buffer, uint16_t value)
{
  assert(buffer != NULL);
  buffer_realloc(buffer, 2);
  *(uint16_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 2;
  return 0;
}

int buffer_write_int16(buffer_t *buffer, int16_t value)
{
  assert(buffer != NULL);
  buffer_realloc(buffer, 2);
  *(int16_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 2;
  return 0;
}

int buffer_write_uint32(buffer_t *buffer, uint32_t value)
{
  assert(buffer != NULL);
  buffer_realloc(buffer, 4);
  *(uint32_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 4;
  return 0;
}

int buffer_write_int32(buffer_t *buffer, int32_t value)
{
  assert(buffer != NULL);
  buffer_realloc(buffer, 4);
  *(int32_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 4;
  return 0;
}

int buffer_write_uint64(buffer_t *buffer, uint64_t value)
{
  assert(buffer != NULL);
  buffer_realloc(buffer, 8);
  *(uint64_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 8;
  return 0;
}

int buffer_write_int64(buffer_t *buffer, int64_t value)
{
  assert(buffer != NULL);
  buffer_realloc(buffer, 8);
  *(int64_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 8;
  return 0;
}

int buffer_write_bytes(buffer_t *buffer, const uint8_t *bytes, uint32_t size)
{
  assert(buffer != NULL);
  assert(bytes != NULL);
  assert(size > 0);
  buffer_write_uint32(buffer, size);
  buffer_write(buffer, bytes, size);
  return 0;
}

int buffer_write_string(buffer_t *buffer, const char *string, uint32_t size)
{
  assert(buffer != NULL);
  assert(string != NULL);
  assert(size > 0);
  return buffer_write_bytes(buffer, (const uint8_t*)string, size);
}

int buffer_write_bytes_long(buffer_t *buffer, const uint8_t *bytes, uint64_t size)
{
  assert(buffer != NULL);
  assert(bytes != NULL);
  assert(size > 0);
  buffer_write_uint64(buffer, size);
  buffer_write(buffer, bytes, size);
  return 0;
}

int buffer_write_string_long(buffer_t *buffer, const char *string, uint64_t size)
{
  assert(buffer != NULL);
  assert(string != NULL);
  assert(size > 0);
  return buffer_write_bytes_long(buffer, (const uint8_t*)string, size);
}
