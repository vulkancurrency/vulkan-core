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

#include <stdint.h>

#include "common/greatest.h"
#include "common/util.h"

#include "common/buffer.h"
#include "common/queue.h"
#include "common/task.h"

SUITE(common_suite);

typedef struct TestQueueObject
{
  int a;
  int b;
  int c;
} test_queue_object_t;

static task_result_t task1_func(task_t *task)
{
  return TASK_RESULT_CONT;
}

static task_result_t task2_func(task_t *task)
{
  return TASK_RESULT_CONT;
}

TEST init_and_free_queue(void)
{
  queue_t *queue = queue_init();
  ASSERT(queue != NULL);
  ASSERT_EQ(queue_free(queue), 0);
  PASS();
}

TEST init_and_shutdown_taskmgr(void)
{
  ASSERT_EQ(taskmgr_init(), 0);
  ASSERT_EQ(taskmgr_shutdown(), 0);
  PASS();
}

TEST init_and_free_buffer(void)
{
  buffer_t *buffer1 = buffer_init();
  ASSERT(buffer1 != NULL);
  ASSERT_EQ(buffer_free(buffer1), 0);
  PASS();
}

TEST insert_object_into_queue_and_pop(void)
{
  queue_t *queue = queue_init();
  ASSERT(queue != NULL);
  ASSERT(queue_get_size(queue) == 0);

  uint16_t a = 0xFF;
  queue_push_left(queue, &a);
  ASSERT(queue_pop_right(queue) == &a);
  ASSERT(queue_get_size(queue) == 0);

  uint64_t b = 0xFFFFFFFE;
  queue_push_right(queue, &b);
  ASSERT(queue_pop_left(queue) == &b);
  ASSERT(queue_get_size(queue) == 0);

  test_queue_object_t *test_queue_object = malloc(sizeof(test_queue_object_t));
  test_queue_object->a = 0;
  test_queue_object->b = 1;
  test_queue_object->c = 2;

  queue_push_left(queue, test_queue_object);
  ASSERT(queue_pop_left(queue) == test_queue_object);
  ASSERT(queue_get_size(queue) == 0);

  queue_push_right(queue, test_queue_object);
  ASSERT(queue_pop_right(queue) == test_queue_object);
  ASSERT(queue_get_size(queue) == 0);
  ASSERT(queue_get_max_index(queue) == -1);

  free(test_queue_object);
  ASSERT_EQ(queue_free(queue), 0);
  PASS();
}

TEST add_remove_and_update_tasks(void)
{
  ASSERT_EQ(taskmgr_init(), 0);

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

  ASSERT(remove_task(task1) == 0);
  ASSERT(remove_task_by_id(task2->id) == 0);

  ASSERT_EQ(taskmgr_shutdown(), 0);
  PASS();
}

TEST pack_and_unpack_buffer(void)
{
  buffer_t *buffer = buffer_init();
  ASSERT(buffer != NULL);

  // pack

  // write messages
  const char *msg = "Hello World!";
  buffer_write_string(buffer, msg, strlen(msg));

  const char *msg1 = "The quick brown fox jumps over the lazy dog.";
  buffer_write_string(buffer, msg1, strlen(msg1));

  const char *msg2 = "THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890";
  buffer_write_string(buffer, msg2, strlen(msg2));

  // write bytes
  const char *data = "\x00\x01\x12Hello World!";
  buffer_write_string(buffer, data, 16);

  const char *data1 = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x44The quick brown fox jumps over the lazy dog.\x00\x00\x01\x00\x00\x00\x00\xfe\x00\xab";
  buffer_write_string(buffer, data, 64);

  const char *data2 = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0fe\xff\x0cb\x02\x003\x00\x01\x02\x03\x04\x05\x06\x07\x08\x62THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG'S BACK 1234567890\x00\x00\x01\x00\x00\x00\x00\xfe\x00\xab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf4";
  buffer_write_string(buffer, data, 128);

  // unpack
  buffer_set_offset(buffer, 0);

  // read messages
  ASSERT_EQ(string_equals(buffer_read_string(buffer), msg), 1);
  ASSERT_EQ(string_equals(buffer_read_string(buffer), msg1), 1);
  ASSERT_EQ(string_equals(buffer_read_string(buffer), msg2), 1);

  // read bytes
  ASSERT_EQ(string_equals(buffer_read_string(buffer), data), 1);
  ASSERT_EQ(string_equals(buffer_read_string(buffer), data1), 1);
  ASSERT_EQ(string_equals(buffer_read_string(buffer), data2), 1);

  ASSERT_EQ(buffer_free(buffer), 0);

  buffer_t *buffer1 = buffer_init();
  ASSERT(buffer1 != NULL);

  // write

  // unsigned
  buffer_write_uint8(buffer1, 0xFF);
  buffer_write_uint16(buffer1, 0xFFFF);
  buffer_write_uint32(buffer1, 0xFFFFFFFF);
  buffer_write_uint64(buffer1, 0xFFFFFFFFFFFFFFFF);

  // signed
  buffer_write_int8(buffer1, 0x7F);
  buffer_write_int16(buffer1, 0x7FFF);
  buffer_write_int32(buffer1, 0x7FFFFFFF);
  buffer_write_int64(buffer1, 0x7FFFFFFFFFFFFFFF);

  buffer_write_int8(buffer1, -0x7F);
  buffer_write_int16(buffer1, -0x7FFF);
  buffer_write_int32(buffer1, -0x7FFFFFFF);
  buffer_write_int64(buffer1, -0x7FFFFFFFFFFFFFFF);

  // read
  buffer_set_offset(buffer1, 0);

  // unsigned
  ASSERT_EQ(buffer_read_uint8(buffer1), 0xFF);
  ASSERT_EQ(buffer_read_uint16(buffer1), 0xFFFF);
  ASSERT_EQ(buffer_read_uint32(buffer1), 0xFFFFFFFF);
  ASSERT_EQ(buffer_read_uint64(buffer1), 0xFFFFFFFFFFFFFFFF);

  // signed
  ASSERT_EQ(buffer_read_int8(buffer1), 0x7F);
  ASSERT_EQ(buffer_read_int16(buffer1), 0x7FFF);
  ASSERT_EQ(buffer_read_int32(buffer1), 0x7FFFFFFF);
  ASSERT_EQ(buffer_read_int64(buffer1), 0x7FFFFFFFFFFFFFFF);

  ASSERT_EQ(buffer_read_int8(buffer1), -0x7F);
  ASSERT_EQ(buffer_read_int16(buffer1), -0x7FFF);
  ASSERT_EQ(buffer_read_int32(buffer1), -0x7FFFFFFF);
  ASSERT_EQ(buffer_read_int64(buffer1), -0x7FFFFFFFFFFFFFFF);

  ASSERT_EQ(buffer_free(buffer1), 0);
  PASS();
}

GREATEST_SUITE(common_suite)
{
  RUN_TEST(init_and_free_queue);
  RUN_TEST(init_and_shutdown_taskmgr);
  RUN_TEST(init_and_free_buffer);
  RUN_TEST(insert_object_into_queue_and_pop);
  RUN_TEST(add_remove_and_update_tasks);
  RUN_TEST(pack_and_unpack_buffer);
}
