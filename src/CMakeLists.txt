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

file(GLOB_RECURSE COMMON common/*)
file(GLOB_RECURSE CORE core/*)
file(GLOB_RECURSE CRYPTO crypto/*)
file(GLOB_RECURSE DAEMON daemon/*)
file(GLOB_RECURSE MINER miner/*)
file(GLOB_RECURSE WALLET wallet/*)

source_group(common FILES ${COMMON})
source_group(core FILES ${CORE})
source_group(crypto FILES ${CRYPTO})
source_group(daemon FILES ${DAEMON})
source_group(miner FILES ${MINER})
source_group(wallet FILES ${WALLET})

add_library(common ${COMMON})
add_library(core ${CORE})
add_library(crypto ${CRYPTO})
add_library(daemon ${DAEMON})
add_library(miner ${MINER})
add_library(wallet ${WALLET})

target_link_libraries(core common crypto miner wallet)
target_link_libraries(wallet common core crypto)
target_link_libraries(daemon common core crypto miner wallet)

if(UPNP_STATIC)
  target_link_libraries(core libminiupnpc-static)
else()
  target_link_libraries(core libminiupnpc)
endif()

if (SODIUM_FOUND)
  if(CMAKE_BUILD_TYPE EQUAL "DEBUG")
    target_link_libraries(core ${SODIUM_LIBRARY_DEBUG})
  else()
    target_link_libraries(core ${SODIUM_LIBRARY_RELEASE})
  endif(CMAKE_BUILD_TYPE EQUAL "DEBUG")
else()
  target_link_libraries(core libsodium_Cmake)
endif()

if (ROCKSDB_FOUND)
  target_link_libraries(core ${ROCKSDB_LIBRARIES})
else()
  target_link_libraries(core rocksdb)
endif()

if (UNIX)
  target_link_libraries(common ${CMAKE_THREAD_LIBS_INIT})
  target_link_libraries(core ${CMAKE_THREAD_LIBS_INIT})
endif()

add_executable(${PROJECT_NAME} ${DAEMON})

target_link_libraries(${PROJECT_NAME} daemon)
