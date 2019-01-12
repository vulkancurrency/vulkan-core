# Copyright (c) 2019, The Vulkan Developers.
#
# This file is part of Vulkan.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# You should have received a copy of the MIT License
# along with Vulkan. If not, see <https://opensource.org/licenses/MIT>.

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

cmake_minimum_required(VERSION 3.2)
project(vulkan)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_C_FLAGS "-Wall -Wno-unused-variable")
set(CMAKE_C_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_RELEASE "-O3")

set(PITTACUS_STATIC ON)

if(NOT WIN32)
  include(CheckIncludeFile)

  check_include_file("sys/uio.h" HAVE_SYS_UIO_H)
  check_include_file("sys/poll.h" HAVE_SYS_POLL_H)
  check_include_file("sys/select.h" HAVE_SYS_SELECT_H)

  if(HAVE_SYS_UIO_H)
    add_compile_definitions(HAVE_SYS_UIO_H)
  else()
    message(FATAL_ERROR "Failed to find required header <sys/uio.h>!")
  endif()

  if(HAVE_SYS_POLL_H)
    add_compile_definitions(HAVE_SYS_POLL_H)
  elseif(HAVE_SYS_SELECT_H)
    add_compile_definitions(HAVE_SYS_SELECT_H)
  else()
    message(FATAL_ERROR "Failed to find required header <sys/poll.h, sys/select.h>!")
  endif()
endif()

find_package(Threads QUIET)
if(NOT Threads_FOUND)
  message(FATAL_ERROR "Failed to find pthreads dependency!")
endif()

find_package(Sodium QUIET)
if(NOT SODIUM_FOUND)
  message(FATAL_ERROR "Failed to find libsodium dependency!")
endif()

find_package(RocksDB QUIET)
if(NOT ROCKSDB_FOUND)
  message(FATAL_ERROR "Failed to find rocksdb dependency!")
endif()

include_directories(${SODIUM_INCLUDE_DIR})
include_directories(${ROCKSDB_INCLUDE_DIR})

add_subdirectory(external/protobuf-c)
include_directories(external/protobuf-c)

add_subdirectory(external/protobuf-c-rpc)
include_directories(external/protobuf-c-rpc)

add_subdirectory(external/pittacus)
include_directories(external/pittacus/src)

add_subdirectory(src)
