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
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "logger.h"

static int g_logger_is_open = 0;
static logger_t g_logger;
static const char* g_logger_log_filename = NULL;

void logger_set_log_filename(const char* log_filename)
{
  g_logger_log_filename = log_filename;
}

const char* logger_get_log_filename(void)
{
  return g_logger_log_filename;
}

void logger_set_fp(FILE *fp)
{
  g_logger.fp = fp;
}

FILE* logget_get_fp(void)
{
  return g_logger.fp;
}

void log_set_level(logger_level_t level)
{
  g_logger.level = level;
}

logger_level_t logger_get_level(void)
{
  return g_logger.level;
}

void logger_set_quiet(uint8_t enable)
{
  g_logger.quiet = enable ? 1 : 0;
}

uint8_t logger_get_quiet(void)
{
  return g_logger.quiet;
}

int logger_log(logger_level_t level, const char *file, int line, const char *fmt, ...)
{
  if (g_logger_is_open == 0)
  {
    return 1;
  }

  uint8_t quiet = g_logger.quiet;
  if (level > g_logger.level)
  {
    quiet = 1;
  }

  mtx_lock(&g_logger.lock);

  time_t t = time(NULL);
  struct tm *lt = localtime(&t);

  if (quiet == 0)
  {
    va_list args;
    char buf[16];
    buf[strftime(buf, sizeof(buf), "%H:%M:%S", lt)] = '\0';
#ifdef LOG_USE_COLOR
    fprintf(stderr, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", buf, LOGGING_LEVEL_COLORS[level], LOGGING_LEVEL_NAMES[level], file, line);
#else
    fprintf(stderr, "%s %-5s %s:%d: ", buf, LOGGING_LEVEL_NAMES[level], file, line);
#endif

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
  }

  if (g_logger.fp)
  {
    va_list args;
    char buf[32];
    buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", lt)] = '\0';
    fprintf(g_logger.fp, "%s %-5s %s:%d: ", buf, LOGGING_LEVEL_NAMES[level], file, line);
    va_start(args, fmt);
    vfprintf(g_logger.fp, fmt, args);
    va_end(args);
    fprintf(g_logger.fp, "\n");
    fflush(g_logger.fp);
  }

  mtx_unlock(&g_logger.lock);
  return 0;
}

int logger_open(void)
{
  if (g_logger_is_open)
  {
    return 1;
  }

  FILE *logging_file = fopen(g_logger_log_filename, "w+");
  if (logging_file == NULL)
  {
    LOG_ERROR("Failed to open logger log file: %s!", g_logger_log_filename);
    return 1;
  }

  mtx_init(&g_logger.lock, mtx_plain);
  g_logger.fp = logging_file;
  g_logger.level = LOG_LEVEL_FATAL;
  g_logger_is_open = 1;

  LOG_INFO("Successfully opened log file: %s", g_logger_log_filename);
  return 0;
}

int logger_close(void)
{
  if (g_logger_is_open == 0)
  {
    return 1;
  }

  fclose(g_logger.fp);
  g_logger.fp = NULL;

  mtx_destroy(&g_logger.lock);
  g_logger_is_open = 0;
  return 0;
}
