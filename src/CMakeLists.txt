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

set(SOURCE_FILES
  block.c
  chain.c
  client.c
  main.c
  mempool.c
  merkle.c
  miner.c
  net.c
  packet.c
  queue.c
  transaction.c
  vulkan.pb-c.c
  wallet.c
)

set(HEADER_FILES
  block.h
  chain.h
  chainparams.h
  client.h
  mempool.h
  merkle.h
  miner.h
  net.h
  packet.h
  queue.h
  transaction.h
  version.h
  vulkan.pb-c.h
  wallet.h
)

add_executable(
  ${PROJECT_NAME}
  ${SOURCE_FILES}
  ${HEADER_FILES}
)

target_link_libraries(
  ${PROJECT_NAME}
  ${CMAKE_THREAD_LIBS_INIT}
)

if(CMAKE_BUILD_TYPE EQUAL "DEBUG")
  target_link_libraries(
    ${PROJECT_NAME}
    ${SODIUM_LIBRARY_DEBUG}
  )
else()
  target_link_libraries(
    ${PROJECT_NAME}
    ${SODIUM_LIBRARY_RELEASE}
  )
endif(CMAKE_BUILD_TYPE EQUAL "DEBUG")

target_link_libraries(
  ${PROJECT_NAME}
  ${ROCKSDB_LIBRARIES}
)

if(UPNPC_STATIC)
  target_link_libraries(
    ${PROJECT_NAME}
    libminiupnpc-static
  )
else()
  target_link_libraries(
    ${PROJECT_NAME}
    libminiupnpc
  )
endif()

target_link_libraries(
  ${PROJECT_NAME}
  protobuf-c
)

target_link_libraries(
  ${PROJECT_NAME}
  protobuf-c-rpc
)

if(PITTACUS_STATIC)
  target_link_libraries(
    ${PROJECT_NAME}
    pittacus_static
  )
else()
  target_link_libraries(
    ${PROJECT_NAME}
    pittacus
  )
endif()
