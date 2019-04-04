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
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "buffer.h"

buffer_t* buffer_init_data(size_t offset, const uint8_t *data, size_t size)
{
  buffer_t *buffer = malloc(sizeof(buffer_t));
  buffer->data = NULL;

  if (size > 0)
  {
    buffer->data = malloc(size);
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

void buffer_set_size(buffer_t *buffer, size_t size)
{
  assert(buffer != NULL);
  buffer->size = size;
}

int buffer_get_size(buffer_t *buffer)
{
  assert(buffer != NULL);
  return buffer->size;
}

void buffer_set_offset(buffer_t *buffer, size_t offset)
{
  assert(buffer != NULL);
  buffer->offset = offset;
}

int buffer_get_offset(buffer_t *buffer)
{
  assert(buffer != NULL);
  return buffer->offset;
}

int buffer_copy(buffer_t *buffer, buffer_t *other_buffer)
{
  assert(buffer != NULL);
  assert(other_buffer != NULL);
  assert(buffer_clear(buffer) == 0);
  assert(buffer_realloc(buffer, other_buffer->size) == 0);
  memcpy(buffer->data, other_buffer->data, other_buffer->size);
  buffer->size = other_buffer->size;
  buffer->offset = other_buffer->offset;
  return 0;
}

int buffer_clear(buffer_t *buffer)
{
  assert(buffer != NULL);
  free(buffer->data);
  buffer->data = NULL;
  buffer->size = 0;
  buffer->offset = 0;
  return 0;
}

int buffer_free(buffer_t *buffer)
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
  return 0;
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

  if (buffer->data == NULL)
  {
    buffer->data = malloc(buffer->size + size);
    memset(buffer->data, 0, buffer->size + size);
  }
  else
  {
    uint8_t *data = realloc(buffer->data, buffer->size + size);
    assert(data != NULL);
    buffer->data = data;
  }

  buffer->size += size;
  return 0;
}

int buffer_write(buffer_t *buffer, const uint8_t *data, size_t size)
{
  assert(buffer != NULL);
  buffer_realloc(buffer, size);
  memcpy(buffer->data + buffer->offset, data, size);
  buffer->offset += size;
  return 0;
}

uint8_t* buffer_get_data(buffer_t *buffer)
{
  assert(buffer != NULL);
  return buffer->data;
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

int buffer_write_string(buffer_t *buffer, const char *string, uint32_t size)
{
  assert(buffer != NULL);
  assert(string != NULL);
  uint32_t actual_size = sizeof(char) + size;
  buffer_write_uint32(buffer, actual_size);
  buffer_write(buffer, (const uint8_t*)string, actual_size);
  return 0;
}

int buffer_write_bytes(buffer_t *buffer, uint8_t *bytes, uint32_t size)
{
  assert(buffer != NULL);
  assert(bytes != NULL);
  uint32_t actual_size = sizeof(uint8_t) + size;
  buffer_write_uint32(buffer, actual_size);
  buffer_write(buffer, bytes, actual_size);
  return 0;
}
