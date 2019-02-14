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

#include <stdlib.h>
#include <pthread.h>

#include "queue.h"

queue_t* queue_init(void)
{
  queue_t *queue = malloc(sizeof(queue_t));
  queue->num_objects = 0;
  queue->max_index = -1;

  pthread_mutex_init(&queue->mutex, NULL);
  return queue;
}

int queue_free(queue_t *queue)
{
  for (int i = 0; i <= queue->max_index; i++)
  {
    queue_remove(queue, i);
  }

  queue->num_objects = 0;
  queue->max_index = -1;

  pthread_mutex_destroy(&queue->mutex);
  free(queue);
  return 0;
}

int queue_get_size(queue_t *queue)
{
  return queue->num_objects;
}

int queue_get_empty(queue_t *queue)
{
  return queue->num_objects == 0;
}

int queue_get_full(queue_t *queue)
{
  return queue->num_objects >= MAX_QUEUE_SIZE;
}

int queue_get_max_index(queue_t *queue)
{
  return queue->max_index;
}

int queue_get_index(queue_t *queue, void *queue_object)
{
  int index = -1;
  for (int i = 0; i <= queue->max_index; i++)
  {
    // find this objects index in the array
    if (queue->queue_objects[i] == queue_object)
    {
      index = i;
      break;
    }
  }

  return index;
}

void* queue_get(queue_t *queue, int index)
{
  if (index < 0)
  {
    return NULL;
  }

  return queue->queue_objects[index];
}

int queue_push(queue_t *queue, int index, void *queue_object)
{
  if (index < 0)
  {
    return 1;
  }

  if (queue_get_full(queue))
  {
    return 1;
  }

  queue->queue_objects[index] = queue_object;
  queue->num_objects++;
  if (index > queue->max_index)
  {
    queue->max_index = index;
  }

  return 0;
}

int queue_push_left(queue_t *queue, void *queue_object)
{
  pthread_mutex_lock(&queue->mutex);
  for (int i = queue->max_index + 1; i >= 0; i--)
  {
    // shift all object over right by one index
    queue->queue_objects[i] = queue->queue_objects[i - 1];
  }

  int result = queue_push(queue, 0, queue_object);
  pthread_mutex_unlock(&queue->mutex);
  return result;
}

int queue_push_right(queue_t *queue, void *queue_object)
{
  pthread_mutex_lock(&queue->mutex);
  int result = queue_push(queue, queue->max_index + 1, queue_object);
  pthread_mutex_unlock(&queue->mutex);
  return result;
}

int queue_remove(queue_t *queue, int index)
{
  if (index < 0)
  {
    return 1;
  }

  if (index >= queue->max_index)
  {
    queue->max_index = index - 1;
  }

  queue->queue_objects[index] = NULL;
  queue->num_objects--;
  return 0;
}

int queue_remove_object(queue_t *queue, void *queue_object)
{
  if (!queue_object)
  {
    return 1;
  }

  pthread_mutex_lock(&queue->mutex);
  int index = queue_get_index(queue, queue_object);
  pthread_mutex_unlock(&queue->mutex);
  if (index == -1)
  {
    return 1;
  }

  pthread_mutex_lock(&queue->mutex);
  int result = queue_remove(queue, index);
  pthread_mutex_unlock(&queue->mutex);
  return result;
}

void* queue_pop(queue_t *queue, int index)
{
  void *queue_object = queue_get(queue, index);
  queue_remove(queue, index);
  return queue_object;
}

void* queue_pop_left(queue_t *queue)
{
  pthread_mutex_lock(&queue->mutex);
  void *queue_object = queue_pop(queue, 0);
  for (int i = 1; i <= queue->max_index; i++)
  {
    // shift all object over left by one index
    queue->queue_objects[i - 1] = queue->queue_objects[i];
  }

  // when shifting objects over left, the maximum index in the queue
  // will remain unused in memory until cleared
  queue->queue_objects[queue->max_index] = NULL;
  queue->max_index--;
  pthread_mutex_unlock(&queue->mutex);
  return queue_object;
}

void* queue_pop_right(queue_t *queue)
{
  pthread_mutex_lock(&queue->mutex);
  void *queue_object = queue_pop(queue, queue->max_index);
  pthread_mutex_unlock(&queue->mutex);
  return queue_object;
}
