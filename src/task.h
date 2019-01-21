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

#include <stdarg.h>
#include <pthread.h>

#include "queue.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum TaskResult
{
  TASK_RESULT_DONE = 0,
  TASK_RESULT_CONT,
  TASK_RESULT_WAIT
} task_result_t;

typedef task_result_t (*callable_func_t)();

typedef struct Task
{
  int id;
  callable_func_t func;
  va_list *args;
  int delayable;
  double delay;
  time_t timestamp;
  pthread_mutex_t mutex;
} task_t;

typedef struct TaskScheduler
{
  int id;
  pthread_t thread;
  pthread_attr_t thread_attr;
} task_scheduler_t;

int taskmgr_init(void);
int taskmgr_tick(void);
int taskmgr_run(void);
void* taskmgr_scheduler_run();
int taskmgr_shutdown(void);

int has_task(task_t *task);
int has_task_by_id(int id);

task_t* add_task(callable_func_t func, double delay, ...);

task_t* get_task_by_id(int id);

void remove_task(task_t *task);
void remove_task_by_id(int id);

void free_task(task_t *task);
void free_task_by_id(int id);

int has_scheduler(task_scheduler_t *task_scheduler);
int has_scheduler_by_id(int id);

task_scheduler_t* add_scheduler(void);

task_scheduler_t* get_scheduler_by_id(int id);

void remove_scheduler(task_scheduler_t *task_scheduler);
void remove_scheduler_by_id(int id);

void free_scheduler(task_scheduler_t *task_scheduler);
void free_scheduler_by_id(int id);

#ifdef __cplusplus
}
#endif
