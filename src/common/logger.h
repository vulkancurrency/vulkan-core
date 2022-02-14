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

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#include "tinycthread.h"

#ifndef LOG_USE_COLOR
#define LOG_USE_COLOR
#endif

typedef enum LoggerLevel
{
  LOG_LEVEL_INFO = 0,
  LOG_LEVEL_WARNING,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_TRACE,
  LOG_LEVEL_DEBUG,
  LOG_LEVEL_FATAL,
} logger_level_t;

static const char *LOGGING_LEVEL_NAMES[] = {
  "INFO",
  "WARNING",
  "ERROR",
  "TRACE",
  "DEBUG",
  "FATAL"
};

static const char *LOGGING_LEVEL_COLORS[] = {
  "\x1b[32m",
  "\x1b[33m",
  "\x1b[31m",
  "\x1b[94m",
  "\x1b[36m",
  "\x1b[35m"
};

typedef struct Logger
{
  FILE *fp;
  logger_level_t level;
  uint8_t quiet;
  mtx_t lock;
} logger_t;

#define LOG_TRACE(...) logger_log(LOG_LEVEL_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) logger_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  logger_log(LOG_LEVEL_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARNING(...)  logger_log(LOG_LEVEL_WARNING,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) logger_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_FATAL(...) logger_log(LOG_LEVEL_FATAL, __FILE__, __LINE__, __VA_ARGS__)

void logger_set_log_filename(const char* log_filename);
const char* logger_get_log_filename(void);

void logger_set_fp(FILE *fp);
FILE* logget_get_fp(void);

void log_set_level(logger_level_t level);
logger_level_t logger_get_level(void);

void logger_set_quiet(uint8_t enable);
uint8_t logger_get_quiet(void);

int logger_log(logger_level_t level, const char *file, int line, const char *fmt, ...);

int logger_open(void);
int logger_close(void);
