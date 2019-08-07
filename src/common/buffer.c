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

buffer_t* buffer_make(void)
{
  buffer_t *buffer = malloc(sizeof(buffer_t));
  if (buffer == NULL)
  {
    return NULL;
  }

  buffer->data = NULL;
  buffer->size = 0;
  buffer->offset = 0;
  return buffer;
}

buffer_t* buffer_init_data(size_t offset, const uint8_t *data, size_t size)
{
  buffer_t *buffer = buffer_make();
  if (buffer == NULL)
  {
    return NULL;
  }

  if (size > 0)
  {
    if (data != NULL)
    {
      if (buffer_set_data(buffer, data, size))
      {
        return NULL;
      }
    }
    else
    {
      if (buffer_pad_data(buffer, size))
      {
        return NULL;
      }
    }
  }

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

int buffer_set_data(buffer_t *buffer, const uint8_t *data, size_t size)
{
  assert(buffer != NULL);
  assert(data != NULL);
  assert(size > 0);
  buffer_clear(buffer);
  return buffer_write(buffer, data, size);
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
  if (buffer_set_data(buffer, other_buffer->data, other_buffer->size))
  {
    return 1;
  }

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
  buffer_clear(buffer);
  free(buffer);
}

int buffer_resize(buffer_t *buffer, size_t size)
{
  assert(buffer != NULL);
  assert(size > 0);
  size_t current_size = buffer->size - buffer->offset;
  if (current_size >= size)
  {
    return 0;
  }

  buffer->data = realloc(buffer->data, buffer->size + size);
  if (buffer->data == NULL)
  {
    return 1;
  }

  buffer->size += size;
  return 0;
}

int buffer_write(buffer_t *buffer, const uint8_t *data, size_t size)
{
  assert(buffer != NULL);
  assert(size > 0);
  if (buffer_resize(buffer, size))
  {
    return 1;
  }

  memcpy(buffer->data + buffer->offset, data, size);
  buffer->offset += size;
  return 0;
}

int buffer_pad_data(buffer_t *buffer, size_t size)
{
  assert(buffer != NULL);
  assert(size > 0);

  // create a NULL byte array of specified size
  uint8_t padded_data[size];
  memset(padded_data, 0, size);
  return buffer_write(buffer, padded_data, size);
}

int buffer_write_uint8(buffer_t *buffer, uint8_t value)
{
  assert(buffer != NULL);
  if (buffer_resize(buffer, 1))
  {
    return 1;
  }

  *(uint8_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 1;
  return 0;
}

int buffer_write_int8(buffer_t *buffer, int8_t value)
{
  assert(buffer != NULL);
  if (buffer_resize(buffer, 1))
  {
    return 1;
  }

  *(int8_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 1;
  return 0;
}

int buffer_write_uint16(buffer_t *buffer, uint16_t value)
{
  assert(buffer != NULL);
  if (buffer_resize(buffer, 2))
  {
    return 1;
  }

  *(uint16_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 2;
  return 0;
}

int buffer_write_int16(buffer_t *buffer, int16_t value)
{
  assert(buffer != NULL);
  if (buffer_resize(buffer, 2))
  {
    return 1;
  }

  *(int16_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 2;
  return 0;
}

int buffer_write_uint32(buffer_t *buffer, uint32_t value)
{
  assert(buffer != NULL);
  if (buffer_resize(buffer, 4))
  {
    return 1;
  }

  *(uint32_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 4;
  return 0;
}

int buffer_write_int32(buffer_t *buffer, int32_t value)
{
  assert(buffer != NULL);
  if (buffer_resize(buffer, 4))
  {
    return 1;
  }

  *(int32_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 4;
  return 0;
}

int buffer_write_uint64(buffer_t *buffer, uint64_t value)
{
  assert(buffer != NULL);
  if (buffer_resize(buffer, 8))
  {
    return 1;
  }

  *(uint64_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 8;
  return 0;
}

int buffer_write_int64(buffer_t *buffer, int64_t value)
{
  assert(buffer != NULL);
  if (buffer_resize(buffer, 8))
  {
    return 1;
  }

  *(int64_t*)(buffer->data + buffer->offset) = value;
  buffer->offset += 8;
  return 0;
}

int buffer_write_bytes8(buffer_t *buffer, const uint8_t *bytes, uint8_t size)
{
  assert(buffer != NULL);
  assert(bytes != NULL);
  assert(size > 0);
  if (buffer_write_uint8(buffer, size))
  {
    return 1;
  }

  if (buffer_write(buffer, bytes, size))
  {
    return 1;
  }

  return 0;
}

int buffer_write_string8(buffer_t *buffer, const char *string, uint8_t size)
{
  assert(buffer != NULL);
  assert(string != NULL);
  assert(size > 0);
  return buffer_write_bytes8(buffer, (const uint8_t*)string, size);
}

int buffer_write_bytes16(buffer_t *buffer, const uint8_t *bytes, uint16_t size)
{
  assert(buffer != NULL);
  assert(bytes != NULL);
  assert(size > 0);
  if (buffer_write_uint16(buffer, size))
  {
    return 1;
  }

  if (buffer_write(buffer, bytes, size))
  {
    return 1;
  }

  return 0;
}

int buffer_write_string16(buffer_t *buffer, const char *string, uint16_t size)
{
  assert(buffer != NULL);
  assert(string != NULL);
  assert(size > 0);
  return buffer_write_bytes16(buffer, (const uint8_t*)string, size);
}

int buffer_write_bytes32(buffer_t *buffer, const uint8_t *bytes, uint32_t size)
{
  assert(buffer != NULL);
  assert(bytes != NULL);
  assert(size > 0);
  if (buffer_write_uint32(buffer, size))
  {
    return 1;
  }

  if (buffer_write(buffer, bytes, size))
  {
    return 1;
  }

  return 0;
}

int buffer_write_string32(buffer_t *buffer, const char *string, uint32_t size)
{
  assert(buffer != NULL);
  assert(string != NULL);
  assert(size > 0);
  return buffer_write_bytes32(buffer, (const uint8_t*)string, size);
}

int buffer_write_bytes64(buffer_t *buffer, const uint8_t *bytes, uint64_t size)
{
  assert(buffer != NULL);
  assert(bytes != NULL);
  assert(size > 0);
  if (buffer_write_uint64(buffer, size))
  {
    return 1;
  }

  if (buffer_write(buffer, bytes, size))
  {
    return 1;
  }

  return 0;
}

int buffer_write_string64(buffer_t *buffer, const char *string, uint64_t size)
{
  assert(buffer != NULL);
  assert(string != NULL);
  assert(size > 0);
  return buffer_write_bytes64(buffer, (const uint8_t*)string, size);
}

int buffer_write_bytes(buffer_t *buffer, const uint8_t *bytes, size_t size)
{
  assert(buffer != NULL);
  assert(bytes != NULL);
  assert(size > 0);
  if (size <= UINT8_MAX)
  {
    buffer_write_uint8(buffer, BUFFER_STRING8);
    buffer_write_bytes8(buffer, bytes, size);
    return 0;
  }
  else if (size > UINT8_MAX && size <= UINT16_MAX)
  {
    buffer_write_uint8(buffer, BUFFER_STRING16);
    buffer_write_bytes16(buffer, bytes, size);
    return 0;
  }
  else if (size > UINT16_MAX && size <= UINT32_MAX)
  {
    buffer_write_uint8(buffer, BUFFER_STRING32);
    buffer_write_bytes32(buffer, bytes, size);
    return 0;
  }
  else if (size > UINT32_MAX && size <= UINT64_MAX)
  {
    buffer_write_uint8(buffer, BUFFER_STRING64);
    buffer_write_bytes64(buffer, bytes, size);
    return 0;
  }

  return 1;
}

int buffer_write_string(buffer_t *buffer, const char *string, size_t size)
{
  assert(buffer != NULL);
  assert(string != NULL);
  assert(size > 0);
  return buffer_write_bytes(buffer, (const uint8_t*)string, size);
}

int buffer_write_padded_bytes(buffer_t *buffer, const uint8_t *bytes, size_t size, size_t padded_size)
{
  assert(buffer != NULL);
  assert(bytes != NULL);
  assert(size > 0);
  assert(padded_size > 0);
  if (size > padded_size)
  {
    return 1;
  }

  buffer_write(buffer, bytes, size);
  size_t remaining_padded_size = padded_size - size;
  if (remaining_padded_size > 0)
  {
    if (buffer_pad_data(buffer, remaining_padded_size))
    {
      return 1;
    }
  }

  return 0;
}

int buffer_write_padded_string(buffer_t *buffer, const char *string, size_t size, size_t padded_size)
{
  assert(buffer != NULL);
  assert(string != NULL);
  assert(size > 0);
  assert(padded_size > 0);
  return buffer_write_padded_bytes(buffer, (const uint8_t*)string, size, padded_size);
}
