# Copyright (c) 2024-2025, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required(VERSION 3.5.0)
project(lwsf)

enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
  # Keep windows.h from pulling in WinSock1: boost::asio needs WinSock2, and
  # headers that include windows.h first would otherwise make its
  # socket_types.hpp fail with "WinSock.h has already been included".
  add_compile_definitions(WIN32_LEAN_AND_MEAN)
endif()

option(LWSF_BUILD_TESTS "Build Tests" OFF)
option(LWSF_SANITIZER "Use specific sanitizer" OFF)
if(NOT LWSF_SANITIZER STREQUAL "OFF")
  if (MSVC)
    message(FATAL_ERROR "Cannot sanitize with MSVC")
  else()
    message(STATUS "Using sanitizer=${LWSF_SANITIZER}")
    add_compile_options("-fsanitize=${LWSF_SANITIZER}")
    add_link_options("-fsanitize=${LWSF_SANITIZER}")
  endif()
endif()

if (NOT MONERO_SOURCE_DIR)
  message(FATAL_ERROR "The argument -DMONERO_SOURCE_DIR must specify a location of a monero source tree")
endif()

cmake_path(CONVERT "${MONERO_SOURCE_DIR}" TO_CMAKE_PATH_LIST MONERO_SOURCE_DIR_CONVERTED)
include(FetchContent)
FetchContent_Declare(monero SOURCE_DIR ${MONERO_SOURCE_DIR_CONVERTED} EXCLUDE_FROM_ALL)

if (NOT LWSF_MASTER_ENABLE)
  set(Boost_NO_BOOST_CMAKE ON)
endif ()

if(STATIC)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
endif()

if (NOT monero_POPULATED)
  FetchContent_MakeAvailable(monero)
endif ()

#
# Dependencies specific to lwsf
#

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if (LWSF_MASTER_ENABLE)
  find_package(Boost 1.66 QUIET REQUIRED COMPONENTS filesystem program_options thread CONFIG)
else ()
  find_package(Boost 1.66 QUIET REQUIRED COMPONENTS filesystem program_options thread)
endif()

list(INSERT CMAKE_MODULE_PATH 0
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(STATIC)
  set(sodium_USE_STATIC_LIBS ON)
endif()
find_package(Sodium REQUIRED)

add_library(monero::libraries INTERFACE IMPORTED)

set_property(TARGET monero::libraries PROPERTY
  INTERFACE_INCLUDE_DIRECTORIES
    ${Boost_INCLUDE_DIR}
    "${MONERO_SOURCE_DIR}/contrib/epee/include"
    "${MONERO_SOURCE_DIR}/external"
    "${MONERO_SOURCE_DIR}/external/easylogging++"
    "${MONERO_SOURCE_DIR}/external/rapidjson/include"
    "${MONERO_SOURCE_DIR}/external/supercop/include"
    "${MONERO_SOURCE_DIR}/src"
)
set_property(TARGET monero::libraries PROPERTY
  INTERFACE_LINK_LIBRARIES
    common
    cryptonote_basic
    epee
    mnemonics
    qrcodegen
    wallet_api
)

add_subdirectory(src)
if (LWSF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
