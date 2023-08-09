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

set(UNITTEST_SOURCE_FILES
  block_tests.c
  blockchain_tests.c
  common_tests.c
  crypto_tests.c
  main.c
  mempool_tests.c
  merkle_tests.c
  protocol_tests.c
  transaction_tests.c
)

set(UNITTEST_HEADER_FILES

)

add_executable(tests ${UNITTEST_SOURCE_FILES} ${UNITTEST_HEADER_FILES})

target_link_libraries(tests mongoose)

if (SODIUM_FOUND)
 if(CMAKE_BUILD_TYPE EQUAL "DEBUG")
   target_link_libraries(tests ${SODIUM_LIBRARY_DEBUG})
 else()
   target_link_libraries(tests ${SODIUM_LIBRARY_RELEASE})
 endif(CMAKE_BUILD_TYPE EQUAL "DEBUG")
else()
 target_link_libraries(tests libsodium_Cmake)
endif()

target_link_libraries(tests crypto common core miner wallet)
