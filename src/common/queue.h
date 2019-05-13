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

#include <stdlib.h>
#include <stdint.h>

#include "tinycthread.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_QUEUE_SIZE 1000000

typedef struct Queue
{
  int num_objects;
  int max_index;
  void *queue_objects[MAX_QUEUE_SIZE];
  mtx_t lock;
} queue_t;

queue_t* queue_init(void);
void queue_free(queue_t *queue);

int queue_push(queue_t *queue, int index, void *queue_object);
int queue_push_left(queue_t *queue, void *queue_object);
int queue_push_right(queue_t *queue, void *queue_object);

int queue_get_size(queue_t *queue);
int queue_get_empty(queue_t *queue);
int queue_get_full(queue_t *queue);
int queue_get_max_index(queue_t *queue);
int queue_get_index(queue_t *queue, void *queue_object);
void* queue_get(queue_t *queue, int index);

int queue_remove(queue_t *queue, int index);
int queue_remove_object(queue_t *queue, void *queue_object);

void* queue_pop(queue_t *queue, int index);
void* queue_pop_left(queue_t *queue);
void* queue_pop_right(queue_t *queue);

#ifdef __cplusplus
}
#endif
