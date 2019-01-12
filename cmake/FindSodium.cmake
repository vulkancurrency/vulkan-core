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

find_path(SODIUM_INCLUDE_DIR
    sodium.h
  PATH_SUFFIXES
    include
  PATHS
    ${SODIUMDIR}
    ${SODIUMDIR}/src/libsodium
    $ENV{SODIUMDIR}
    $ENV{SODIUMDIR}/src/libsodium
    ~/Library/Frameworks
    /Library/Frameworks
    /usr/local/
    /usr/
    /sw          # Fink
    /opt/local/  # DarwinPorts
    /opt/csw/    # Blastwave
    /opt/
)

set(SODIUM_FOUND TRUE)
set(FIND_SODIUM_LIB_PATHS
  ${SODIUMDIR}
  $ENV{SODIUMDIR}
  ~/Library/Frameworks
  /Library/Frameworks
  /usr/local
  /usr
  /sw
  /opt/local
  /opt/csw
  /opt
)

find_library(SODIUM_LIBRARY_DEBUG
  NAMES
    sodium
    libsodium
  PATH_SUFFIXES
    lib64
    lib
  PATHS
    ${FIND_SODIUM_LIB_PATHS}
    ${SODIUMDIR}/bin/Win32/Debug/v120/dynamic
    $ENV{SODIUMDIR}/bin/Win32/Debug/v120/dynamic
)

find_library(SODIUM_LIBRARY_RELEASE
  NAMES
    sodium
    libsodium
  PATH_SUFFIXES
    lib64
    lib
  PATHS
    ${FIND_SODIUM_LIB_PATHS}
    ${SODIUMDIR}/bin/Win32/Release/v120/dynamic
    $ENV{SODIUMDIR}/bin/Win32/Release/v120/dynamic
)

if (SODIUM_LIBRARY_DEBUG OR SODIUM_LIBRARY_RELEASE)
  if (SODIUM_LIBRARY_DEBUG AND SODIUM_LIBRARY_RELEASE)
    set(SODIUM_LIBRARY debug ${SODIUM_LIBRARY_DEBUG} optimized ${SODIUM_LIBRARY_RELEASE})
  endif()

  if (SODIUM_LIBRARY_DEBUG AND NOT SODIUM_LIBRARY_RELEASE)
    set(SODIUM_LIBRARY_RELEASE ${SODIUM_LIBRARY_DEBUG})
    set(SODIUM_LIBRARY ${SODIUM_LIBRARY_DEBUG})
  endif()
  if (SODIUM_LIBRARY_RELEASE AND NOT SODIUM_LIBRARY_DEBUG)
    set(SODIUM_LIBRARY_DEBUG ${SODIUM_LIBRARY_RELEASE})
    set(SODIUM_LIBRARY ${SODIUM_LIBRARY_RELEASE})
  endif()
else()
  set(SODIUM_FOUND FALSE)
  set(SODIUM_LIBRARY "")
  set(FIND_SODIUM_MISSING "${FIND_SODIUM_MISSING} SODIUM_LIBRARY")
endif()

mark_as_advanced(
  SODIUM_LIBRARY
  SODIUM_LIBRARY_RELEASE
  SODIUM_LIBRARY_DEBUG
)

set(SODIUM_LIBRARIES ${SODIUM_LIBRARIES} "${SODIUM_LIBRARY}")

if (NOT SODIUM_FOUND)
  set(FIND_SODIUM_ERROR "Could NOT find Sodium (missing: ${FIND_SODIUM_MISSING})")
  if(SODIUM_FIND_REQUIRED)
    message(FATAL_ERROR ${FIND_SODIUM_ERROR})
  elseif(NOT SODIUM_FIND_QUIETLY)
    message("${FIND_SODIUM_ERROR}")
  endif()
endif()

if(SODIUM_FOUND)
  message("Found Sodium: ${SODIUM_INCLUDE_DIR}")
endif()
