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
#include <stdio.h>
#include <string.h>

#include "buffer.h"

buffer_t* buffer_init_data(int offset, const uint8_t *data, int size)
{
  buffer_t *buffer = malloc(sizeof(buffer_t));
  if (size > 0)
  {
    buffer->data = malloc(size);
    memcpy(buffer->data, data, size);
  }
  else
  {
    buffer->data = NULL;
  }

  buffer->size = size;
  buffer->offset = offset;
  return buffer;
}

buffer_t* buffer_init_size(int offset, int size)
{
  const uint8_t *data = NULL;
  return buffer_init_data(offset, data, size);
}

buffer_t* buffer_init_offset(int offset)
{
  return buffer_init_size(offset, 0);
}

buffer_t* buffer_init(void)
{
  return buffer_init_offset(0);
}

void buffer_set_size(buffer_t *buffer, int size)
{
  buffer->size = size;
}

int buffer_get_size(buffer_t *buffer)
{
  return buffer->size;
}

void buffer_set_offset(buffer_t *buffer, int offset)
{
  buffer->offset = offset;
}

int buffer_get_offset(buffer_t *buffer)
{
  return buffer->offset;
}

int buffer_copy(buffer_t *buffer, buffer_t *other_buffer)
{
  buffer_realloc(buffer, other_buffer->size);
  memcpy(buffer->data, other_buffer->data, other_buffer->size);
  buffer->size = other_buffer->size;
  buffer->offset = other_buffer->offset;
  return 0;
}

int buffer_free(buffer_t *buffer)
{
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

int buffer_realloc(buffer_t *buffer, int size)
{
  // resize the array if there isn't enough memory
  // pre-allocated...
  if (buffer_get_remaining_size(buffer) < size)
  {
    uint8_t *data = malloc(buffer->size + size);
    memcpy(data, buffer->data, buffer->size);
    buffer->data = data;
    buffer->size += size;
  }

  return 0;
}

int buffer_write(buffer_t *buffer, const uint8_t *data, int size)
{
  buffer_realloc(buffer, size);
  memcpy(buffer->data + buffer->offset, data, size);
  buffer->offset += size;
  return 0;
}

uint8_t* buffer_read(buffer_t *buffer, int size)
{
  uint8_t *data = malloc(size);
  memcpy(data, buffer->data + buffer->offset, size);
  buffer->offset += size;
  buffer->size -= size;
  return data;
}

int buffer_get_remaining_size(buffer_t *buffer)
{
  return buffer_get_size(buffer) - buffer->offset;
}

const unsigned char* buffer_get_data(buffer_t *buffer)
{
  return buffer->data;
}

const unsigned char* buffer_get_remaining_data(buffer_t *buffer)
{
  return buffer->data + buffer->offset;
}

int buffer_write_uint8(buffer_t *buffer, uint8_t value)
{
  buffer_realloc(buffer, 1);
  *(uint8_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 1;
  return 0;
}

uint8_t buffer_read_uint8(buffer_t *buffer)
{
  uint8_t value = *(uint8_t*)(buffer->data + buffer->offset);
  buffer->offset += 1;
  buffer->size -= 1;
  return value;
}

int buffer_write_int8(buffer_t *buffer, int8_t value)
{
  buffer_realloc(buffer, 1);
  *(int8_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 1;
  return 0;
}

int8_t buffer_read_int8(buffer_t *buffer)
{
  int8_t value = *(int8_t*)(buffer->data + buffer->offset);
  buffer->offset += 1;
  buffer->size -= 1;
  return value;
}

int buffer_write_uint16(buffer_t *buffer, uint16_t value)
{
  buffer_realloc(buffer, 2);
  *(uint16_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 2;
  return 0;
}

uint16_t buffer_read_uint16(buffer_t *buffer)
{
  uint16_t value = *(uint16_t*)(buffer->data + buffer->offset);
  buffer->offset += 2;
  buffer->size -= 2;
  return value;
}

int buffer_write_int16(buffer_t *buffer, int16_t value)
{
  buffer_realloc(buffer, 2);
  *(int16_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 2;
  return 0;
}

int16_t buffer_read_int16(buffer_t *buffer)
{
  int16_t value = *(int16_t*)(buffer->data + buffer->offset);
  buffer->offset += 2;
  buffer->size -= 2;
  return value;
}

int buffer_write_uint32(buffer_t *buffer, uint32_t value)
{
  buffer_realloc(buffer, 4);
  *(uint32_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 4;
  return 0;
}

uint32_t buffer_read_uint32(buffer_t *buffer)
{
  uint32_t value = *(uint32_t*)(buffer->data + buffer->offset);
  buffer->offset += 4;
  buffer->size -= 4;
  return value;
}

int buffer_write_int32(buffer_t *buffer, int32_t value)
{
  buffer_realloc(buffer, 4);
  *(int32_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 4;
  return 0;
}

int32_t buffer_read_int32(buffer_t *buffer)
{
  int32_t value = *(int32_t*)(buffer->data + buffer->offset);
  buffer->offset += 4;
  buffer->size -= 4;
  return value;
}

int buffer_write_uint64(buffer_t *buffer, uint64_t value)
{
  buffer_realloc(buffer, 8);
  *(uint64_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 8;
  return 0;
}

uint64_t buffer_read_uint64(buffer_t *buffer)
{
  uint64_t value = *(uint64_t*)(buffer->data + buffer->offset);
  buffer->offset += 8;
  buffer->size -= 8;
  return value;
}

int buffer_write_int64(buffer_t *buffer, int64_t value)
{
  buffer_realloc(buffer, 8);
  *(int64_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 8;
  return 0;
}

int64_t buffer_read_int64(buffer_t *buffer)
{
  int64_t value = *(int64_t*)(buffer->data + buffer->offset);
  buffer->offset += 8;
  buffer->size -= 8;
  return value;
}

int buffer_write_string(buffer_t *buffer, const char *string, uint32_t size)
{
  uint32_t actual_size = sizeof(const char*) + size;
  buffer_write_uint32(buffer, actual_size);
  buffer_write(buffer, (const uint8_t*)string, actual_size);
  return 0;
}

char* buffer_read_string(buffer_t *buffer)
{
  return (char*)buffer_read(buffer, buffer_read_uint32(buffer));
}

int buffer_write_bytes(buffer_t *buffer, uint8_t *bytes, uint32_t size)
{
  uint32_t actual_size = sizeof(uint8_t*) + size;
  buffer_write_uint32(buffer, actual_size);
  buffer_write(buffer, bytes, actual_size);
  return 0;
}

uint8_t* buffer_read_bytes(buffer_t *buffer)
{
  return buffer_read(buffer, buffer_read_uint32(buffer));
}

int buffer_write_raw_string(buffer_t *buffer, const char *string, uint32_t size)
{
  uint32_t actual_size = sizeof(const char*) + size;
  buffer_write(buffer, (const uint8_t*)string, actual_size);
  return 0;
}

int buffer_write_raw_bytes(buffer_t *buffer, uint8_t *bytes, uint32_t size)
{
  uint32_t actual_size = sizeof(uint8_t*) + size;
  buffer_write(buffer, bytes, actual_size);
  return 0;
}
