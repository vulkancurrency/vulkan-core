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
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include <deque.h>

#include "task.h"
#include "tinycthread.h"
#include "util.h"

static int g_taskmgr_next_task_id = -1;
static int g_taskmgr_next_scheduler_id = -1;

static Deque *g_taskmgr_tasks = NULL;
static Deque *g_taskmgr_schedulers = NULL;

static int g_taskmgr_running = 0;

int taskmgr_init(void)
{
  if (g_taskmgr_running)
  {
    return 1;
  }

  if (deque_new(&g_taskmgr_tasks) != CC_OK)
  {
    return 1;
  }

  if (deque_new(&g_taskmgr_schedulers) != CC_OK)
  {
    return 1;
  }

  g_taskmgr_running = 1;
  return 0;
}

int taskmgr_tick(void)
{
  if (deque_size(g_taskmgr_tasks) > 0)
  {
    void *val = NULL;
    int r = deque_remove_first(g_taskmgr_tasks, &val);
    assert(r == CC_OK);
    task_t *task = (task_t*)val;
    assert(task != NULL);

    if (task->delayable)
    {
      if (get_current_time() - task->timestamp < task->delay)
      {
        r = deque_add_last(g_taskmgr_tasks, task);
        assert(r == CC_OK);
        return 0;
      }
    }

    mtx_lock(&task->lock);
    va_list args;
    va_copy(args, *task->args);
    task_result_t result = task->func(task, args);
    va_end(args);
    mtx_unlock(&task->lock);

    // process the task result and determine what the
    // task should do next...
    switch (result)
    {
      case TASK_RESULT_CONT:
        {
          task->delayable = 0;
          r = deque_add_last(g_taskmgr_tasks, task);
          assert(r == CC_OK);
        }
        break;
      case TASK_RESULT_WAIT:
        {
          task->delayable = 1;
          task->timestamp = get_current_time();
          r = deque_add_last(g_taskmgr_tasks, task);
          assert(r == CC_OK);
        }
        break;
      case TASK_RESULT_DONE:
      default:
        free_task(task);
        break;
    }
  }

  return 0;
}

int taskmgr_run(void)
{
  if (g_taskmgr_running)
  {
    return 1;
  }

  g_taskmgr_running = 1;
  while (g_taskmgr_running)
  {
    if (taskmgr_tick())
    {
      return 1;
    }

    // call yield and give another thread a chance
    // to use the CPU resources for other tasks...
    thrd_yield();
  }

  return 0;
}

int taskmgr_scheduler_run()
{
  while (g_taskmgr_running)
  {
    if (taskmgr_tick())
    {
      return 1;
    }

    // call yield and give another thread a chance
    // to use the CPU resources for other tasks...
    thrd_yield();
  }

  return 0;
}

int taskmgr_shutdown(void)
{
  if (g_taskmgr_running == 0)
  {
    return 1;
  }

  deque_destroy(g_taskmgr_tasks);
  deque_destroy(g_taskmgr_schedulers);

  g_taskmgr_running = 0;
  return 0;
}

int has_task(task_t *task)
{
  return deque_contains(g_taskmgr_tasks, task) > 0;
}

int has_task_by_id(int id)
{
  return get_task_by_id(id) != NULL;
}

task_t* add_task(callable_func_t func, double delay, ...)
{
  va_list args;
  va_start(args, delay);

  g_taskmgr_next_task_id++;

  task_t* task = malloc(sizeof(task_t));
  task->id = g_taskmgr_next_task_id;
  task->func = func;
  task->args = &args;
  task->delayable = 1;
  task->delay = delay;
  task->timestamp = get_current_time();
  mtx_init(&task->lock, mtx_recursive);

  int r = deque_add_last(g_taskmgr_tasks, task);
  assert(r == CC_OK);
  return task;
}

task_t* get_task_by_id(int id)
{
  void *val = NULL;
  DEQUE_FOREACH(val, g_taskmgr_tasks,
  {
    task_t *task = (task_t*)val;
    assert(task != NULL);

    if (task->id == id)
    {
      return task;
    }
  })

  return NULL;
}

void print_task(task_t *task)
{
  printf("Task: id=%u, delayable=%u, delay=%.6f, timestamp=%u\n", task->id, task->delayable, task->delay, task->timestamp);
}

void print_tasks(void)
{
  void *val = NULL;
  DEQUE_FOREACH(val, g_taskmgr_tasks,
  {
    task_t *task = (task_t*)val;
    assert(task != NULL);
    print_task(task);
  })
}

int remove_task(task_t *task)
{
  int r = deque_remove(g_taskmgr_tasks, task, NULL);
  free_task(task);
  return r == CC_OK;
}

int remove_task_by_id(int id)
{
  task_t *task = get_task_by_id(id);
  if (task == NULL)
  {
    return 0;
  }

  return remove_task(task);
}

void free_task(task_t *task)
{
  assert(task != NULL);
  va_end(*task->args);

  task->id = -1;
  task->delayable = 0;
  task->delay = 0;
  task->timestamp = 0;

  mtx_destroy(&task->lock);
  free(task);
}

void free_task_by_id(int id)
{
  task_t *task = get_task_by_id(id);
  assert(task != NULL);
  free_task(task);
}

int has_scheduler(task_scheduler_t *task_scheduler)
{
  return deque_contains(g_taskmgr_schedulers, task_scheduler) > 0;
}

int has_scheduler_by_id(int id)
{
  return get_scheduler_by_id(id) != NULL;
}

task_scheduler_t* add_scheduler(void)
{
  g_taskmgr_next_scheduler_id++;

  task_scheduler_t* task_scheduler = malloc(sizeof(task_scheduler_t));
  task_scheduler->id = g_taskmgr_next_scheduler_id;

  if (thrd_create(&task_scheduler->thread, taskmgr_scheduler_run, NULL) != thrd_success)
  {
    fprintf(stderr, "Failed to initialize thread: %d!\n", g_taskmgr_next_scheduler_id);
    return NULL;
  }

  int r = deque_add_last(g_taskmgr_schedulers, task_scheduler);
  assert(r == CC_OK);
  return task_scheduler;
}

task_scheduler_t* get_scheduler_by_id(int id)
{

  void *val = NULL;
  DEQUE_FOREACH(val, g_taskmgr_schedulers,
  {
    task_scheduler_t *task_scheduler = (task_scheduler_t*)val;
    assert(task_scheduler != NULL);

    if (task_scheduler->id == id)
    {
      return task_scheduler;
    }
  })

  return NULL;
}

int remove_scheduler(task_scheduler_t *task_scheduler)
{
  int r = deque_remove(g_taskmgr_schedulers, task_scheduler, NULL);
  free_scheduler(task_scheduler);
  return r == CC_OK;
}

int remove_scheduler_by_id(int id)
{
  task_scheduler_t *task_scheduler = get_scheduler_by_id(id);
  if (task_scheduler == NULL)
  {
    return 1;
  }

  return remove_scheduler(task_scheduler);
}

void free_scheduler(task_scheduler_t *task_scheduler)
{
  assert(task_scheduler != NULL);
  free(task_scheduler);
}

void free_scheduler_by_id(int id)
{
  task_scheduler_t *task_scheduler = get_scheduler_by_id(id);
  assert(task_scheduler != NULL);
  free_scheduler(task_scheduler);
}
