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

set(VULKAN_WALLET_SOURCE_FILES
  wallet.c
)

set(VULKAN_WALLET_HEADER_FILES
  wallet.h
)

add_library(wallet ${VULKAN_WALLET_SOURCE_FILES}
                   ${VULKAN_WALLET_HEADER_FILES})

if (SODIUM_FOUND)
 if(CMAKE_BUILD_TYPE EQUAL "DEBUG")
   target_link_libraries(wallet ${SODIUM_LIBRARY_DEBUG})
 else()
   target_link_libraries(wallet ${SODIUM_LIBRARY_RELEASE})
 endif(CMAKE_BUILD_TYPE EQUAL "DEBUG")
else()
 target_link_libraries(wallet libsodium_Cmake)
endif()

if (WITH_LEVELDB)
 if (LEVELDB_FOUND)
   target_link_libraries(wallet ${LEVELDB_LIBRARIES})
 else()
   target_link_libraries(wallet leveldb)
 endif()
elseif (WITH_LMDB)
 target_link_libraries(wallet lmdb)
elseif (WITH_ROCKSDB)
 if (ROCKSDB_FOUND)
   target_link_libraries(wallet ${ROCKSDB_LIBRARIES})
 else()
   target_link_libraries(wallet rocksdb)
 endif()
endif()
