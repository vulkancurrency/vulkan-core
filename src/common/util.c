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
#include <stdio.h>
#include <stdint.h>
#include <ftw.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#ifdef _WIN32
 #include <sysinfoapi.h>
#endif

#include "util.h"

#include "crypto/sha256d.h"

uint16_t get_num_logical_cores(void)
{
#ifdef _WIN32
  SYSTEM_INFO sysinfo;
  GetSystemInfo(&sysinfo);
  return sysinfo.dwNumberOfProcessors;
#else
  return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

int string_equals(const char *string, const char *equals)
{
  return strcmp(string, equals) == 0;
}

int string_startswith(const char *string, const char *prefix)
{
  return strncmp(prefix, string, strlen(prefix)) == 0;
}

int string_endswith(const char *string, const char *ext)
{
  int ext_length = strlen(ext);
  return strncmp(ext, &string[strlen(string) - ext_length], ext_length) == 0;
}

int string_count(const char *string, const char *countstr, int countbreak)
{
  int count = 0;
  for (int i = 0; i <= strlen(string) - 1; i++)
  {
    if (string_startswith(&string[i], countstr))
    {
      count++;
    }
    else
    {
      if (countbreak)
      {
        break;
      }
    }
  }

  return count;
}

const char* string_copy(const char *string, const char *other_string)
{
  int size = sizeof(char*) * (strlen(string) + strlen(other_string));
  char* out_string = malloc(size);
  memset(out_string, '\0', size);

  strncpy(out_string, string, strlen(string));
  strncpy(out_string + strlen(string), other_string, strlen(other_string));

  return (const char*)out_string;
}

int make_hash(char *digest, unsigned char *string)
{
  unsigned char hash[crypto_hash_sha256_BYTES];
  crypto_hash_sha256d(hash, string, strlen((char*)string));

  for (int i = 0; i < crypto_hash_sha256_BYTES; i++)
  {
    sprintf(&digest[i*2], "%02x", (unsigned int) hash[i]);
  }

  return 0;
}

const char* hash_to_str(uint8_t in_hash[HASH_SIZE])
{
  int hash_len = (crypto_hash_sha256_BYTES * 2) + 1;
  char *out_hash = malloc(sizeof(char) * hash_len);
  for (int i = 0; i < crypto_hash_sha256_BYTES; i++)
  {
    sprintf(out_hash + (i * 2), "%02x", (unsigned int)in_hash[i]);
  }

  return (const char*)out_hash;
}

const char* address_to_str(uint8_t in_address[ADDRESS_SIZE])
{
  int address_len = (ADDRESS_SIZE * 2) + 1;
  char *out_address = malloc(sizeof(char) * address_len);
  for (int i = 0; i < ADDRESS_SIZE; i++)
  {
    sprintf(out_address + (i * 2), "%02x", (unsigned int)in_address[i]);
  }

  return (const char*)out_address;
}

uint32_t get_current_time(void)
{
  return (uint32_t)time(NULL);
}

static int unlink_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
  int rv = remove(fpath);
  if (rv)
  {
    perror(fpath);
  }

  return rv;
}

int rmrf(const char *path)
{
  return nftw(path, unlink_callback, 64, FTW_DEPTH | FTW_PHYS);
}

static int sort_compare(const void* a, const void* b)
{
  int c = *((int*)a);
  int d = *((int*)b);
  return (c > d) - (c < d);
}

void sort(void *base, size_t nitems, size_t size)
{
  qsort(base, nitems, size, sort_compare);
}
