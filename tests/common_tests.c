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
#include <stdlib.h>
#include <stdint.h>

#include "common/buffer_iterator.h"
#include "common/buffer.h"
#include "common/buffer_storage.h"
#include "common/greatest.h"
#include "common/task.h"
#include "common/util.h"

SUITE(common_suite);

static const char *g_buffer_storage_dir = "buffer_storage_tests.dat";

static task_result_t task1_func(task_t *task)
{
  return TASK_RESULT_CONT;
}

static task_result_t task2_func(task_t *task)
{
  return TASK_RESULT_CONT;
}

TEST buffer_common_tests(void)
{
  buffer_t *buffer = buffer_init();
  ASSERT(buffer != NULL);
  ASSERT(buffer_get_size(buffer) == 0);

  // pack

  // write messages
  const char *msg = "Hello World!";
  ASSERT(buffer_write_string32(buffer, msg, strlen(msg)) == 0);

  const char *msg1 = "The quick brown fox jumps over the lazy dog.";
  ASSERT(buffer_write_string32(buffer, msg1, strlen(msg1)) == 0);

  const char *msg2 = "THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890";
  ASSERT(buffer_write_string32(buffer, msg2, strlen(msg2)) == 0);

  // write bytes
  const char *data = "\x00\x01\x12Hello World!";
  ASSERT(buffer_write_string32(buffer, data, 16) == 0);
  ASSERT(buffer_write_bytes32(buffer, (uint8_t*)data, 16) == 0);

  const char *data1 = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x44The quick brown fox jumps over the lazy dog.\x00\x00\x01\x00\x00\x00\x00\xfe\x00\xab";
  ASSERT(buffer_write_string32(buffer, data1, 64) == 0);
  ASSERT(buffer_write_bytes32(buffer, (uint8_t*)data1, 64) == 0);

  const char *data2 = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0fe\xff\x0cb\x02\x003\x00\x01\x02\x03\x04\x05\x06\x07\x08\x62THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890\x00\x00\x01\x00\x00\x00\x00\xfe\x00\xab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf4";
  ASSERT(buffer_write_string32(buffer, data2, 128) == 0);
  ASSERT(buffer_write_bytes32(buffer, (uint8_t*)data2, 128) ==0);

  // unpack
  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer);

  // read messages
  char *str = NULL;
  uint8_t *bytes = NULL;

  ASSERT(buffer_read_string32(buffer_iterator, &str) == 0);
  ASSERT_MEM_EQ(str, msg, strlen(msg));

  ASSERT(buffer_read_string32(buffer_iterator, &str) == 0);
  ASSERT_MEM_EQ(str, msg1, strlen(msg1));

  ASSERT(buffer_read_string32(buffer_iterator, &str) == 0);
  ASSERT_MEM_EQ(str, msg2, strlen(msg2));

  // read bytes
  ASSERT(buffer_read_string32(buffer_iterator, &str) == 0);
  ASSERT_MEM_EQ(str, data, strlen(data));

  ASSERT(buffer_read_bytes32(buffer_iterator, &bytes) == 0);
  ASSERT_MEM_EQ(bytes, data, strlen(data));

  ASSERT(buffer_read_string32(buffer_iterator, &str) == 0);
  ASSERT_MEM_EQ(str, data1, strlen(data1));

  ASSERT(buffer_read_bytes32(buffer_iterator, &bytes) == 0);
  ASSERT_MEM_EQ(bytes, data1, strlen(data1));

  ASSERT(buffer_read_string32(buffer_iterator, &str) == 0);
  ASSERT_MEM_EQ(str, data2, strlen(data2));

  ASSERT(buffer_read_bytes32(buffer_iterator, &bytes) == 0);
  ASSERT_MEM_EQ(bytes, data2, strlen(data2));

  ASSERT(buffer_get_remaining_size(buffer_iterator) == 0);
  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);

  buffer_t *buffer1 = buffer_init();
  ASSERT(buffer1 != NULL);
  ASSERT(buffer_get_size(buffer1) == 0);

  // write

  // unsigned
  ASSERT(buffer_write_uint8(buffer1, 0xFF) == 0);
  ASSERT(buffer_write_uint16(buffer1, 0xFFFF) == 0);
  ASSERT(buffer_write_uint32(buffer1, 0xFFFFFFFF) == 0);
  ASSERT(buffer_write_uint64(buffer1, 0xFFFFFFFFFFFFFFFF) == 0);

  // signed
  ASSERT(buffer_write_int8(buffer1, 0x7F) == 0);
  ASSERT(buffer_write_int16(buffer1, 0x7FFF) == 0);
  ASSERT(buffer_write_int32(buffer1, 0x7FFFFFFF) == 0);
  ASSERT(buffer_write_int64(buffer1, 0x7FFFFFFFFFFFFFFF) == 0);

  ASSERT(buffer_write_int8(buffer1, -0x7F) == 0);
  ASSERT(buffer_write_int16(buffer1, -0x7FFF) == 0);
  ASSERT(buffer_write_int32(buffer1, -0x7FFFFFFF) == 0);
  ASSERT(buffer_write_int64(buffer1, -0x7FFFFFFFFFFFFFFF) == 0);

  // copy the contents of buffer1 to buffer2
  buffer_t *buffer2 = buffer_init();
  ASSERT(buffer2 != NULL);
  ASSERT(buffer_copy(buffer2, buffer1) == 0);
  ASSERT_EQ(buffer_get_size(buffer2), buffer_get_size(buffer1));
  ASSERT_EQ(string_equals((char*)buffer_get_data(buffer1), (char*)buffer_get_data(buffer2)), 1);
  buffer_free(buffer2);

  // read
  buffer_iterator_t *buffer_iterator1 = buffer_iterator_init(buffer1);

  // unsigned
  uint8_t v1 = 0;
  ASSERT(buffer_read_uint8(buffer_iterator1, &v1) == 0);
  ASSERT_EQ(v1, 0xFF);

  uint16_t v2 = 0;
  ASSERT(buffer_read_uint16(buffer_iterator1, &v2) == 0);
  ASSERT_EQ(v2, 0xFFFF);

  uint32_t v3 = 0;
  ASSERT(buffer_read_uint32(buffer_iterator1, &v3) == 0);
  ASSERT_EQ(v3, 0xFFFFFFFF);

  uint64_t v4 = 0;
  ASSERT(buffer_read_uint64(buffer_iterator1, &v4) == 0);
  ASSERT_EQ(v4, 0xFFFFFFFFFFFFFFFF);

  // signed
  int8_t v5 = 0;
  ASSERT(buffer_read_int8(buffer_iterator1, &v5) == 0);
  ASSERT_EQ(v5, 0x7F);

  int16_t v6 = 0;
  ASSERT(buffer_read_int16(buffer_iterator1, &v6) == 0);
  ASSERT_EQ(v6, 0x7FFF);

  int32_t v7 = 0;
  ASSERT(buffer_read_int32(buffer_iterator1, &v7) == 0);
  ASSERT_EQ(v7, 0x7FFFFFFF);

  int64_t v8 = 0;
  ASSERT(buffer_read_int64(buffer_iterator1, &v8) == 0);
  ASSERT_EQ(v8, 0x7FFFFFFFFFFFFFFF);

  int8_t v9 = 0;
  ASSERT(buffer_read_int8(buffer_iterator1, &v9) == 0);
  ASSERT_EQ(v9, -0x7F);

  int16_t v10 = 0;
  ASSERT(buffer_read_int16(buffer_iterator1, &v10) == 0);
  ASSERT_EQ(v10, -0x7FFF);

  int32_t v11 = 0;
  ASSERT(buffer_read_int32(buffer_iterator1, &v11) == 0);
  ASSERT_EQ(v11, -0x7FFFFFFF);

  int64_t v12 = 0;
  ASSERT(buffer_read_int64(buffer_iterator1, &v12) == 0);
  ASSERT_EQ(v12, -0x7FFFFFFFFFFFFFFF);

  ASSERT(buffer_get_remaining_size(buffer_iterator1) == 0);
  buffer_iterator_free(buffer_iterator1);
  buffer_free(buffer1);

  // try and compare a buffer to another buffer
  buffer_t *buffer_cmp1 = buffer_init();
  buffer_t *buffer_cmp2 = buffer_init();

  const char *some_string_str = "Hello World from buffer cmp test!";
  ASSERT(buffer_write_string32(buffer_cmp1, some_string_str, strlen(some_string_str)) == 0);
  ASSERT(buffer_write_string32(buffer_cmp2, some_string_str, strlen(some_string_str)) == 0);
  ASSERT(buffer_compare(buffer_cmp1, buffer_cmp1) == 1);

  // compare buffer iterators
  buffer_iterator_t *buffer_iterator_cmp1 = buffer_iterator_init(buffer_cmp1);
  buffer_iterator_t *buffer_iterator_cmp2 = buffer_iterator_init(buffer_cmp2);
  ASSERT(buffer_iterator_compare(buffer_iterator_cmp1, buffer_iterator_cmp2) == 1);

  buffer_iterator_free(buffer_iterator_cmp1);
  buffer_iterator_free(buffer_iterator_cmp2);

  buffer_free(buffer_cmp1);
  buffer_free(buffer_cmp2);

  PASS();
}

TEST buffer_storage_common_tests(void)
{
  char *err = NULL;
  buffer_storage_t *buffer_storage = buffer_storage_open(g_buffer_storage_dir, &err);
  if (err != NULL)
  {
    fprintf(stderr, "%s\n", err);
    FAIL();
  }

  buffer_t *buffer = buffer_init();
  ASSERT(buffer != NULL);

  const char *data = "\x00\x01\x12Hello World!";
  ASSERT(buffer_write_string32(buffer, data, 16) == 0);
  ASSERT(buffer_write_bytes32(buffer, (uint8_t*)data, 16) == 0);

  const char *data1 = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x44The quick brown fox jumps over the lazy dog.\x00\x00\x01\x00\x00\x00\x00\xfe\x00\xab";
  ASSERT(buffer_write_string32(buffer, data1, 64) == 0);
  ASSERT(buffer_write_bytes32(buffer, (uint8_t*)data1, 64) == 0);

  const char *data2 = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0fe\xff\x0cb\x02\x003\x00\x01\x02\x03\x04\x05\x06\x07\x08\x62THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890\x00\x00\x01\x00\x00\x00\x00\xfe\x00\xab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf4";
  ASSERT(buffer_write_string32(buffer, data2, 128) == 0);
  ASSERT(buffer_write_bytes32(buffer, (uint8_t*)data2, 128) == 0);

  // write the buffer
  if (buffer_storage_write_buffer(buffer_storage, buffer, &err))
  {
    ASSERT(err != NULL);
    fprintf(stderr, "%s\n", err);
    FAIL();
  }

  // read buffer from the database
  buffer_t *buffer1 = NULL;
  if (buffer_storage_read_buffer(buffer_storage, &buffer1, &err))
  {
    ASSERT(err != NULL);
    fprintf(stderr, "%s\n", err);
    FAIL();
  }

  ASSERT(buffer1 != NULL);
  buffer_iterator_t *buffer_iterator = buffer_iterator_init(buffer1);
  ASSERT(buffer_iterator != NULL);

  // compare the contents of the buffer
  char *str = NULL;
  uint8_t *bytes = NULL;

  ASSERT(buffer_read_string32(buffer_iterator, &str) == 0);
  ASSERT_MEM_EQ(str, data, strlen(data));

  ASSERT(buffer_read_bytes32(buffer_iterator, &bytes) == 0);
  ASSERT_MEM_EQ(bytes, data, strlen(data));

  ASSERT(buffer_read_string32(buffer_iterator, &str) == 0);
  ASSERT_MEM_EQ(str, data1, strlen(data1));

  ASSERT(buffer_read_bytes32(buffer_iterator, &bytes) == 0);
  ASSERT_MEM_EQ(bytes, data1, strlen(data1));

  ASSERT(buffer_read_string32(buffer_iterator, &str) == 0);
  ASSERT_MEM_EQ(str, data2, strlen(data2));

  ASSERT(buffer_read_bytes32(buffer_iterator, &bytes) == 0);
  ASSERT_MEM_EQ(bytes, data2, strlen(data2));

  ASSERT(buffer_get_remaining_size(buffer_iterator) == 0);
  buffer_iterator_free(buffer_iterator);
  buffer_free(buffer);
  buffer_free(buffer1);

  if (buffer_storage_close(buffer_storage))
  {
    fprintf(stderr, "Failed to close buffer database!\n");
    FAIL();
  }

  buffer_storage_free(buffer_storage);
  if (buffer_storage_remove(g_buffer_storage_dir, &err))
  {
    fprintf(stderr, "Failed to remove buffer database: %s\n", err);
    FAIL();
  }

  PASS();
}

TEST task_common_tests(void)
{
  task_t *task1 = add_task(task1_func, 0);
  task_t *task2 = add_task(task2_func, 0);

  ASSERT(task1 != NULL);
  ASSERT(task2 != NULL);

  ASSERT(get_task_by_id(task1->id) != NULL);
  ASSERT(get_task_by_id(task2->id) != NULL);

  ASSERT(has_task(task1) == 1);
  ASSERT(has_task_by_id(task2->id) == 1);

  int tick_result1 = taskmgr_tick();
  int tick_result2 = taskmgr_tick();
  int tick_result3 = taskmgr_tick();

  ASSERT(has_task(task1) == 1);
  ASSERT(has_task_by_id(task2->id) == 1);

  ASSERT_EQ(tick_result1, 0);
  ASSERT_EQ(tick_result2, 0);
  ASSERT_EQ(tick_result3, 0);

  ASSERT(remove_task(task1));
  ASSERT(remove_task_by_id(task2->id));
  PASS();
}

GREATEST_SUITE(common_suite)
{
  RUN_TEST(buffer_common_tests);
  RUN_TEST(buffer_storage_common_tests);
  RUN_TEST(task_common_tests);
}
