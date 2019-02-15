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

#include "common/greatest.h"

#include "common/queue.h"
#include "common/task.h"

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

SUITE(common_suite);

TEST init_and_free_queue(void)
{
  queue_t *queue = queue_init();
  ASSERT(queue != NULL);
  queue_free(queue);
  PASS();
}

TEST init_and_shutdown_taskmgr(void)
{
  taskmgr_init();
  taskmgr_shutdown();
  PASS();
}

TEST insert_object_into_queue_and_pop(void)
{
  queue_t *queue = queue_init();
  ASSERT(queue_get_size(queue) == 0);

  int a = 0xFF;
  queue_push_left(queue, &a);
  ASSERT(queue_pop_right(queue) == &a);
  ASSERT(queue_get_size(queue) == 0);

  int b = 0xFFFFFFFE;
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
  queue_free(queue);
  PASS();
}

TEST add_remove_and_update_tasks(void)
{
  taskmgr_init();

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

  taskmgr_shutdown();
  PASS();
}

GREATEST_SUITE(common_suite)
{
  RUN_TEST(init_and_free_queue);
  RUN_TEST(init_and_shutdown_taskmgr);
  RUN_TEST(insert_object_into_queue_and_pop);
  RUN_TEST(add_remove_and_update_tasks);
}
