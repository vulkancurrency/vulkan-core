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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <sodium.h>

#ifdef _WIN32
 #include <sysinfoapi.h>
#endif

#include "util.h"

#include "crypto/cryptoutil.h"
#include "crypto/sha256d.h"

unsigned concatenate(unsigned x, unsigned y)
{
  unsigned pow = 10;
  while (y >= pow)
  {
    pow *= 10;
  }

  return x * pow + y;
}

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

char* bin2hex(uint8_t *bin, size_t bin_size)
{
  char *hex = malloc((bin_size * 2) + 1);
  for (int i = 0; i < bin_size; i++)
  {
    sprintf(hex + (i * 2), "%02x", (unsigned int)bin[i]);
  }

  return hex;
}

uint8_t* hex2bin(const char *hexstr, size_t *size)
{
  size_t hexstr_len = strlen(hexstr);
  size_t bytes_len = hexstr_len / 2;

  uint8_t* bytes = (uint8_t*)malloc(bytes_len);
  int count = 0;
  const char* pos = hexstr;

  for (count = 0; count < bytes_len; count++)
  {
    sscanf(pos, "%2hhx", &bytes[count]);
    pos += 2;
  }

  if (size != NULL)
  {
    *size = bytes_len;
  }

  return bytes;
}

uint32_t get_current_time(void)
{
  return (uint32_t)time(NULL);
}

int cmp_least_greatest(const void *a, const void *b)
{
  int f = *((int*)a);
  int s = *((int*)b);
  if (f > s)
  {
    return 1;
  }

  if (f < s)
  {
    return -1;
  }

  return 0;
}

int is_private_address(uint32_t ip)
{
  uint8_t bytes[4];
  bytes[0] = ip & 0xFF;
  bytes[1] = (ip >> 8) & 0xFF;
  bytes[2] = (ip >> 16) & 0xFF;
  bytes[3] = (ip >> 24) & 0xFF;

  // 10.x.y.z
  if (bytes[0] == 10)
  {
    return 1;
  }

  // 172.16.0.0 - 172.31.255.255
  if ((bytes[0] == 172) && (bytes[1] >= 16) && (bytes[1] <= 31))
  {
    return 1;
  }

  // 192.168.0.0 - 192.168.255.255
  if ((bytes[0] == 192) && (bytes[1] == 168))
  {
    return 1;
  }

  return 0;
}

int is_local_address(uint32_t ip)
{
  uint8_t bytes[4];
  bytes[0] = ip & 0xFF;
  bytes[1] = (ip >> 8) & 0xFF;
  bytes[2] = (ip >> 16) & 0xFF;
  bytes[3] = (ip >> 24) & 0xFF;

  // 0.0.0.0
  if (ip == 0)
  {
    return 1;
  }

  // 127.0.0.1
  if ((bytes[0] == 1) && (bytes[1] == 0) && (bytes[2] == 0) && (bytes[3] == 127))
  {
    return 1;
  }

  return 0;
}

char* convert_ip_to_str(uint32_t ip)
{
  char *out = malloc(sizeof(char) * 15);
  uint8_t bytes[4];

  bytes[0] = ip & 0xFF;
  bytes[1] = (ip >> 8) & 0xFF;
  bytes[2] = (ip >> 16) & 0xFF;
  bytes[3] = (ip >> 24) & 0xFF;

  sprintf(out, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
  return out;
}

uint32_t convert_str_to_ip(const char* address)
{
  uint32_t v = 0;
  int i;
  const char *start;

  start = address;
  for (i = 0; i < 4; i++)
  {
      char c;
      int n = 0;
      for (;;)
      {
        c = * start;
        start++;
        if (c >= '0' && c <= '9')
        {
          n *= 10;
          n += c - '0';
        }
        else if ((i < 3 && c == '.') || i == 3)
        {
          break;
        }
        else
        {
          return 0;
        }
      }

      if (n >= 256)
      {
        return 0;
      }

      v *= 256;
      v += n;
  }

  return v;
}

char* convert_to_addr_str(const char* address, uint32_t port)
{
  char *out = malloc(strlen(address) + sizeof(port) + 1);
  sprintf(out, "%s:%u", address, port);
  return out;
}
