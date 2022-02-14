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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include "buffer.h"
#include "buffer_storage.h"

buffer_storage_t* buffer_storage_make(void)
{
  buffer_storage_t *buffer_storage = malloc(sizeof(buffer_storage_t));
  if (buffer_storage == NULL)
  {
    return NULL;
  }

  buffer_storage->mode = "ab+";
  buffer_storage->open = 0;
  buffer_storage->fp = NULL;
  return buffer_storage;
}

void buffer_storage_free(buffer_storage_t *buffer_storage)
{
  assert(buffer_storage != NULL);
  assert(buffer_storage->open == 0);
  free(buffer_storage);
}

void buffer_storage_set_mode(buffer_storage_t *buffer_storage, const char *mode)
{
  assert(buffer_storage != NULL);
  buffer_storage->mode = mode;
}

const char* buffer_storage_get_mode(buffer_storage_t *buffer_storage)
{
  assert(buffer_storage != NULL);
  return buffer_storage->mode;
}

buffer_storage_t* buffer_storage_open(const char *filepath, char **err)
{
  buffer_storage_t *buffer_storage = buffer_storage_make();
  if (buffer_storage == NULL)
  {
    *err = "Failed to open buffer database, could not allocate sufficient memory!";
    return NULL;
  }

  // open the file for reading and writing bytes
  buffer_storage->fp = fopen(filepath, buffer_storage->mode);
  if (buffer_storage->fp == NULL)
  {
    *err = "Failed to open buffer database!";
    return NULL;
  }

  buffer_storage->open = 1;
  return buffer_storage;
}

int buffer_storage_close(buffer_storage_t *buffer_storage)
{
  assert(buffer_storage != NULL);
  assert(buffer_storage->fp != NULL);
  if (buffer_storage->open == 0)
  {
    return 1;
  }

  if (fclose(buffer_storage->fp) != 0)
  {
    return 1;
  }

  buffer_storage->mode = NULL;
  buffer_storage->open = 0;
  buffer_storage->fp = NULL;
  return 0;
}

int buffer_storage_remove(const char *filepath, char **err)
{
  if (remove(filepath) != 0)
  {
    *err = "Failed to remove buffer database, file does not exist!";
    return 1;
  }

  return 0;
}

int buffer_storage_write_buffer(buffer_storage_t *buffer_storage, buffer_t *buffer, char **err)
{
  assert(buffer_storage != NULL);
  assert(buffer_storage->fp != NULL);
  assert(buffer != NULL);
  if (buffer_storage->open == 0)
  {
    *err = "Failed to write buffer database, database is not open!";
    return 1;
  }

  uint8_t *data = buffer_get_data(buffer);
  assert(data != NULL);
  size_t data_len = buffer_get_size(buffer);
  assert(data_len > 0);

  // write the data to the file
  fseek(buffer_storage->fp, 0L, SEEK_SET);
  size_t bytes_written = fwrite(data, 1, data_len, buffer_storage->fp);
  if (bytes_written != data_len)
  {
    *err = "Failed to write buffer database, left over bytes remain!";
    return 1;
  }

  fseek(buffer_storage->fp, 0L, SEEK_SET);
  return 0;
}

int buffer_storage_read_buffer(buffer_storage_t *buffer_storage, buffer_t **buffer_out, char **err)
{
  assert(buffer_storage != NULL);
  assert(buffer_storage->fp != NULL);
  if (buffer_storage->open == 0)
  {
    *err = "Failed to read buffer database, database is not open!";
    return 1;
  }

  // get the file size so we know how many bytes to read
  fseek(buffer_storage->fp, 0L, SEEK_END);
  size_t data_len = ftell(buffer_storage->fp);
  fseek(buffer_storage->fp, 0L, SEEK_SET);

  // read the bytes from disk and place them into a buffer
  uint8_t data[data_len];
  size_t bytes_read = fread(data, 1, data_len, buffer_storage->fp);
  if (bytes_read != data_len)
  {
    *err = "Failed to read buffer database, did not read all bytes!";
    return 1;
  }

  fseek(buffer_storage->fp, 0L, SEEK_SET);
  *buffer_out = buffer_init_data(0, data, data_len);
  return 0;
}
