# Copyright (c) 2019-2022, The Vulkan Developers.
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

set(VULKAN_COMMON_SOURCE_FILES
  argparse.c
  buffer_database.c
  buffer_iterator.c
  buffer.c
  logger.c
  task.c
  tinycthread.c
  util.c
  vec.c
)

set(VULKAN_COMMON_HEADER_FILES
  argparse.h
  buffer_database.h
  buffer_iterator.h
  buffer.h
  greatest.h
  byteorder.h
  logger.h
  task.h
  tinycthread.h
  util.h
  vulkan.h
)

add_library(common ${VULKAN_COMMON_SOURCE_FILES}
                   ${VULKAN_COMMON_HEADER_FILES})

if (UNIX)
 target_link_libraries(common ${CMAKE_THREAD_LIBS_INIT})
endif()

target_link_libraries(common collectc)
