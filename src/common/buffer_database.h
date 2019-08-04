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

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

#include "buffer.h"
#include "vulkan.h"

VULKAN_BEGIN_DECL

typedef struct BufferDatabase
{
  const char *mode;
  int open;
  FILE *fp;
} buffer_database_t;

VULKAN_API buffer_database_t* buffer_database_make(void);
VULKAN_API void buffer_database_free(buffer_database_t *buffer_database);

VULKAN_API void buffer_database_set_mode(buffer_database_t *buffer_database, const char *mode);
VULKAN_API const char* buffer_database_get_mode(buffer_database_t *buffer_database);

VULKAN_API buffer_database_t* buffer_database_open(const char *filepath, char **err);
VULKAN_API int buffer_database_close(buffer_database_t *buffer_database);
VULKAN_API int buffer_database_remove(const char *filepath, char **err);

VULKAN_API int buffer_database_write_buffer(buffer_database_t *buffer_database, buffer_t *buffer, char **err);
VULKAN_API int buffer_database_read_buffer(buffer_database_t *buffer_database, buffer_t **buffer_out, char **err);

VULKAN_END_DECL
