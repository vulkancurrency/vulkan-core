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

set(VULKAN_CORE_SOURCE_FILES
  block.c
  blockchain.c
  checkpoints.c
  console.c
  genesis.c
  mempool.c
  merkle.c
  net.c
  p2p.c
  parameters.c
  pow.c
  protocol.c
  transaction_builder.c
  transaction.c
)

set(VULKAN_CORE_HEADER_FILES
  block.h
  blockchain.h
  checkpoint_data.h
  checkpoints.h
  console.h
  genesis.h
  mempool.h
  merkle.h
  net.h
  p2p.h
  parameters.h
  pow.h
  protocol.h
  seed_nodes.h
  transaction_builder.h
  transaction.h
  version.h
)

add_library(core ${VULKAN_CORE_SOURCE_FILES}
                 ${VULKAN_CORE_HEADER_FILES})

if (SODIUM_FOUND)
 if(CMAKE_BUILD_TYPE EQUAL "DEBUG")
   target_link_libraries(core ${SODIUM_LIBRARY_DEBUG})
 else()
   target_link_libraries(core ${SODIUM_LIBRARY_RELEASE})
 endif(CMAKE_BUILD_TYPE EQUAL "DEBUG")
else()
 target_link_libraries(core libsodium_Cmake)
endif()

if (WITH_LEVELDB)
 if (LEVELDB_FOUND)
   target_link_libraries(core ${LEVELDB_LIBRARIES})
 else()
   target_link_libraries(core leveldb)
 endif()
elseif (WITH_LMDB)
 target_link_libraries(core lmdb)
elseif (WITH_ROCKSDB)
 if (ROCKSDB_FOUND)
   target_link_libraries(core ${ROCKSDB_LIBRARIES})
 else()
   target_link_libraries(core rocksdb)
 endif()
endif()

if (BUILD_STATIC)
  target_link_libraries(core libminiupnpc-static)
else()
  target_link_libraries(core libminiupnpc)
endif()
