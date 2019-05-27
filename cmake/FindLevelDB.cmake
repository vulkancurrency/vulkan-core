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

include(FindPackageHandleStandardArgs)

if(leveldb_FIND_REQUIRED)
  set(_LEVELDB_output_type FATAL_ERROR)
  set(_LEVELDB_output 1)
else()
  set(_LEVELDB_output_type STATUS)
  if(leveldb_FIND_QUIETLY)
    set(_LEVELDB_output)
  else()
    set(_LEVELDB_output 1)
  endif()
endif()

find_path(_LEVELDB_INCLUDE_DIR leveldb/db.h
  HINTS ${CMAKE_SOURCE_DIR}/../../.. $ENV{LEVELDB_ROOT} ${LEVELDB_ROOT}
  PATH_SUFFIXES include
  PATHS /usr /usr/local /opt /opt/local)

if(EXISTS "${_LEVELDB_INCLUDE_DIR}/leveldb/version.h")
  set(_LEVELDB_Version_file "${_LEVELDB_INCLUDE_DIR}/leveldb/version.h")
elseif(EXISTS "${_LEVELDB_INCLUDE_DIR}/leveldb/db.h")
  set(_LEVELDB_Version_file "${_LEVELDB_INCLUDE_DIR}/leveldb/db.h")
endif()
if(_LEVELDB_INCLUDE_DIR AND _LEVELDB_Version_file)
  file(READ ${_LEVELDB_Version_file} _LEVELDB_header_contents)
  string(REGEX REPLACE ".*kMajorVersion = ([0-9]+).*kMinorVersion = ([0-9]+).*"
    "\\1.\\2" _LEVELDB_VERSION "${_LEVELDB_header_contents}")
  string(REGEX REPLACE ".*LEVELDB_MAJOR ([0-9]+).*LEVELDB_MINOR ([0-9]+).*"
    "\\1.\\2" _LEVELDB_VERSION "${_LEVELDB_header_contents}")
  set(LEVELDB_VERSION ${_LEVELDB_VERSION} CACHE INTERNAL
    "The version of leveldb which was detected")
else()
  set(_LEVELDB_EPIC_FAIL TRUE)
  if(_LEVELDB_output)
    message(${_LEVELDB_output_type}
      "Can't find leveldb header file leveldb/db.h.")
  endif()
endif()

# Version checking
if(LEVELDB_FIND_VERSION AND LEVELDB_VERSION)
  if(LEVELDB_FIND_VERSION_EXACT)
    if(NOT LEVELDB_VERSION VERSION_EQUAL ${LEVELDB_FIND_VERSION})
      set(_LEVELDB_version_not_exact TRUE)
    endif()
  else()
    # version is too low
    if(NOT LEVELDB_VERSION VERSION_EQUAL ${LEVELDB_FIND_VERSION} AND
        NOT LEVELDB_VERSION VERSION_GREATER ${LEVELDB_FIND_VERSION})
      set(_LEVELDB_version_not_high_enough TRUE)
    endif()
  endif()
endif()

find_library(LEVELDB_LIBRARY leveldb
  HINTS ${CMAKE_SOURCE_DIR}/../../.. $ENV{LEVELDB_ROOT} ${LEVELDB_ROOT}
  PATH_SUFFIXES lib lib64
  PATHS /usr /usr/local /opt /opt/local)

# Inform the users with an error message based on what version they
# have vs. what version was required.
if(NOT LEVELDB_VERSION)
  set(_LEVELDB_EPIC_FAIL TRUE)
  if(_LEVELDB_output)
    message(${_LEVELDB_output_type}
      "Version not found in ${_LEVELDB_Version_file}.")
  endif()
elseif(_LEVELDB_version_not_high_enough)
  set(_LEVELDB_EPIC_FAIL TRUE)
  if(_LEVELDB_output)
    message(${_LEVELDB_output_type}
      "Version ${LEVELDB_FIND_VERSION} or higher of leveldb is required. "
      "Version ${LEVELDB_VERSION} was found in ${_LEVELDB_Version_file}.")
  endif()
elseif(_LEVELDB_version_not_exact)
  set(_LEVELDB_EPIC_FAIL TRUE)
  if(_LEVELDB_output)
    message(${_LEVELDB_output_type}
      "Version ${LEVELDB_FIND_VERSION} of leveldb is required exactly. "
      "Version ${LEVELDB_VERSION} was found.")
  endif()
else()
  if(LEVELDB_FIND_REQUIRED)
    if(LEVELDB_LIBRARY MATCHES "LEVELDB_LIBRARY-NOTFOUND")
      message(FATAL_ERROR "Missing the leveldb library.\n"
        "Consider using CMAKE_PREFIX_PATH or the LEVELDB_ROOT environment variable. "
        "See the ${CMAKE_CURRENT_LIST_FILE} for more details.")
    endif()
  endif()
  find_package_handle_standard_args(LEVELDB DEFAULT_MSG
                                    LEVELDB_LIBRARY _LEVELDB_INCLUDE_DIR)
endif()

if(_LEVELDB_EPIC_FAIL)
  # Zero out everything, we didn't meet version requirements
  set(LEVELDB_FOUND FALSE)
  set(LEVELDB_LIBRARY)
  set(_LEVELDB_INCLUDE_DIR)
  set(LEVELDB_INCLUDE_DIRS)
  set(LEVELDB_LIBRARIES)
else()
  set(LEVELDB_INCLUDE_DIRS ${_LEVELDB_INCLUDE_DIR})
  set(LEVELDB_LIBRARIES ${LEVELDB_LIBRARY})
  if(_LEVELDB_output)
    message(STATUS
      "Found leveldb ${LEVELDB_VERSION} in ${LEVELDB_INCLUDE_DIRS};${LEVELDB_LIBRARIES}")
  endif()
endif()
