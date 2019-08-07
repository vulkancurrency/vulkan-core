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
#include <stdint.h>

#include "buffer_iterator.h"
#include "buffer.h"

buffer_iterator_t* buffer_iterator_make(void)
{
  buffer_iterator_t *buffer_iterator = malloc(sizeof(buffer_iterator_t));
  if (buffer_iterator == NULL)
  {
    return NULL;
  }

  buffer_iterator->buffer = NULL;
  buffer_iterator->offset = 0;
  return buffer_iterator;
}

buffer_iterator_t* buffer_iterator_init(const buffer_t *buffer)
{
  assert(buffer != NULL);
  buffer_iterator_t *buffer_iterator = buffer_iterator_make();
  if (buffer_iterator == NULL)
  {
    return NULL;
  }

  buffer_iterator->buffer = buffer;
  return buffer_iterator;
}

void buffer_iterator_free(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  free(buffer_iterator);
}

void buffer_iterator_set_buffer(buffer_iterator_t *buffer_iterator, const buffer_t *buffer)
{
  assert(buffer_iterator != NULL);
  assert(buffer != NULL);
  buffer_iterator->buffer = buffer;
  buffer_iterator->offset = 0;
}

const buffer_t *buffer_iterator_get_buffer(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  return buffer_iterator->buffer;
}

void buffer_iterator_set_offset(buffer_iterator_t *buffer_iterator, size_t offset)
{
  assert(buffer_iterator != NULL);
  buffer_iterator->offset = offset;
}

size_t buffer_iterator_get_offset(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  return buffer_iterator->offset;
}

int buffer_iterator_compare(buffer_iterator_t *buffer_iterator, buffer_iterator_t *other_buffer_iterator)
{
  assert(buffer_iterator != NULL);
  assert(other_buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  assert(other_buffer_iterator->buffer != NULL);
  return (
    buffer_compare((buffer_t*)buffer_iterator->buffer, (buffer_t*)other_buffer_iterator->buffer) &&
    buffer_iterator->offset == other_buffer_iterator->offset);
}

void buffer_iterator_clear(buffer_iterator_t *buffer_iterator)
{
  assert(buffer_iterator != NULL);
  buffer_iterator->buffer = NULL;
  buffer_iterator->offset = 0;
}

int buffer_read(buffer_iterator_t *buffer_iterator, size_t size, uint8_t **bytes)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  if (buffer_get_remaining_size(buffer_iterator) < size)
  {
    return 1;
  }

  uint8_t *data = malloc(size);
  if (data == NULL)
  {
    return 1;
  }

  memcpy(data, buffer_iterator->buffer->data + buffer_iterator->offset, size);
  *bytes = data;
  buffer_iterator->offset += size;
  return 0;
}

size_t buffer_get_remaining_size(buffer_iterator_t *buffer_iterator)
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

int buffer_read_uint8(buffer_iterator_t *buffer_iterator, uint8_t *value)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  if (buffer_get_remaining_size(buffer_iterator) < 1)
  {
    return 1;
  }

  const buffer_t *buffer = buffer_iterator->buffer;
  assert(buffer != NULL);

  size_t offset = buffer_iterator->offset;
  buffer_iterator->offset += 1;
  *value = (uint8_t)buffer->data[offset];
  return 0;
}

int buffer_read_int8(buffer_iterator_t *buffer_iterator, int8_t *value)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  if (buffer_get_remaining_size(buffer_iterator) < 1)
  {
    return 1;
  }

  const buffer_t *buffer = buffer_iterator->buffer;
  assert(buffer != NULL);

  size_t offset = buffer_iterator->offset;
  buffer_iterator->offset += 1;
  *value = (int8_t)buffer->data[offset];
  return 0;
}

int buffer_read_uint16(buffer_iterator_t *buffer_iterator, uint16_t *value)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  if (buffer_get_remaining_size(buffer_iterator) < 2)
  {
    return 1;
  }

  const buffer_t *buffer = buffer_iterator->buffer;
  assert(buffer != NULL);

  size_t offset = buffer_iterator->offset;
  buffer_iterator->offset += 2;
  *value = (uint16_t)buffer->data[offset + 1] << 8 |
           (uint16_t)buffer->data[offset + 0] << 0;

  return 0;
}

int buffer_read_int16(buffer_iterator_t *buffer_iterator, int16_t *value)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  if (buffer_get_remaining_size(buffer_iterator) < 2)
  {
    return 1;
  }

  const buffer_t *buffer = buffer_iterator->buffer;
  assert(buffer != NULL);

  size_t offset = buffer_iterator->offset;
  buffer_iterator->offset += 2;
  *value = (int16_t)buffer->data[offset + 1] << 8 |
           (int16_t)buffer->data[offset + 0] << 0;

  return 0;
}

int buffer_read_uint32(buffer_iterator_t *buffer_iterator, uint32_t *value)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  if (buffer_get_remaining_size(buffer_iterator) < 4)
  {
    return 1;
  }

  const buffer_t *buffer = buffer_iterator->buffer;
  assert(buffer != NULL);

  size_t offset = buffer_iterator->offset;
  buffer_iterator->offset += 4;
  *value = (uint32_t)buffer->data[offset + 3] << 24 |
           (uint32_t)buffer->data[offset + 2] << 16 |
           (uint32_t)buffer->data[offset + 1] <<  8 |
           (uint32_t)buffer->data[offset + 0] <<  0;

  return 0;
}

int buffer_read_int32(buffer_iterator_t *buffer_iterator, int32_t *value)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  if (buffer_get_remaining_size(buffer_iterator) < 4)
  {
    return 1;
  }

  const buffer_t *buffer = buffer_iterator->buffer;
  assert(buffer != NULL);

  size_t offset = buffer_iterator->offset;
  buffer_iterator->offset += 4;
  *value = (int32_t)buffer->data[offset + 3] << 24 |
           (int32_t)buffer->data[offset + 2] << 16 |
           (int32_t)buffer->data[offset + 1] <<  8 |
           (int32_t)buffer->data[offset + 0] <<  0;

  return 0;
}

uint64_t buffer_read_uint64(buffer_iterator_t *buffer_iterator, uint64_t *value)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  if (buffer_get_remaining_size(buffer_iterator) < 8)
  {
    return 1;
  }

  const buffer_t *buffer = buffer_iterator->buffer;
  assert(buffer != NULL);

  size_t offset = buffer_iterator->offset;
  buffer_iterator->offset += 8;
  *value = (uint64_t)buffer->data[offset + 7] << 56 |
           (uint64_t)buffer->data[offset + 6] << 48 |
           (uint64_t)buffer->data[offset + 5] << 40 |
           (uint64_t)buffer->data[offset + 4] << 32 |
           (uint64_t)buffer->data[offset + 3] << 24 |
           (uint64_t)buffer->data[offset + 2] << 16 |
           (uint64_t)buffer->data[offset + 1] <<  8 |
           (uint64_t)buffer->data[offset + 0] <<  0;

  return 0;
}

int buffer_read_int64(buffer_iterator_t *buffer_iterator, int64_t *value)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  if (buffer_get_remaining_size(buffer_iterator) < 8)
  {
    return 1;
  }

  const buffer_t *buffer = buffer_iterator->buffer;
  assert(buffer != NULL);

  size_t offset = buffer_iterator->offset;
  buffer_iterator->offset += 8;
  *value = (int64_t)buffer->data[offset + 7] << 56 |
           (int64_t)buffer->data[offset + 6] << 48 |
           (int64_t)buffer->data[offset + 5] << 40 |
           (int64_t)buffer->data[offset + 4] << 32 |
           (int64_t)buffer->data[offset + 3] << 24 |
           (int64_t)buffer->data[offset + 2] << 16 |
           (int64_t)buffer->data[offset + 1] <<  8 |
           (int64_t)buffer->data[offset + 0] <<  0;

  return 0;
}

int buffer_read_bytes8(buffer_iterator_t *buffer_iterator, uint8_t **bytes)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint8_t size = 0;
  if (buffer_read_uint8(buffer_iterator, &size))
  {
    return 1;
  }

  return buffer_read(buffer_iterator, size, bytes);
}

int buffer_read_string8(buffer_iterator_t *buffer_iterator, char **string)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  return buffer_read_bytes8(buffer_iterator, (uint8_t**)string);
}

int buffer_read_bytes16(buffer_iterator_t *buffer_iterator, uint8_t **bytes)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint16_t size = 0;
  if (buffer_read_uint16(buffer_iterator, &size))
  {
    return 1;
  }

  return buffer_read(buffer_iterator, size, bytes);
}

int buffer_read_string16(buffer_iterator_t *buffer_iterator, char **string)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  return buffer_read_bytes16(buffer_iterator, (uint8_t**)string);
}

int buffer_read_bytes32(buffer_iterator_t *buffer_iterator, uint8_t **bytes)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint32_t size = 0;
  if (buffer_read_uint32(buffer_iterator, &size))
  {
    return 1;
  }

  return buffer_read(buffer_iterator, size, bytes);
}

int buffer_read_string32(buffer_iterator_t *buffer_iterator, char **string)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  return buffer_read_bytes32(buffer_iterator, (uint8_t**)string);
}

int buffer_read_bytes64(buffer_iterator_t *buffer_iterator, uint8_t **bytes)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint64_t size = 0;
  if (buffer_read_uint64(buffer_iterator, &size))
  {
    return 1;
  }

  return buffer_read(buffer_iterator, size, bytes);
}

int buffer_read_string64(buffer_iterator_t *buffer_iterator, char **string)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  return buffer_read_bytes64(buffer_iterator, (uint8_t**)string);
}

int buffer_read_bytes(buffer_iterator_t *buffer_iterator, uint8_t **bytes)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  uint8_t string_type = 0;
  if (buffer_read_uint8(buffer_iterator, &string_type))
  {
    return 1;
  }

  switch (string_type)
  {
    case BUFFER_STRING8:
      return buffer_read_bytes8(buffer_iterator, bytes);
    case BUFFER_STRING16:
      return buffer_read_bytes16(buffer_iterator, bytes);
    case BUFFER_STRING32:
      return buffer_read_bytes32(buffer_iterator, bytes);
    case BUFFER_STRING64:
      return buffer_read_bytes64(buffer_iterator, bytes);
    default:
      return 1;
  }

  return 0;
}

int buffer_read_string(buffer_iterator_t *buffer_iterator, char **string)
{
  assert(buffer_iterator != NULL);
  assert(buffer_iterator->buffer != NULL);
  return buffer_read_bytes(buffer_iterator, (uint8_t**)string);
}
