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

if (NOT MONERO_SOURCE_DIR)
  message(FATAL_ERROR "The argument -DMONERO_SOURCE_DIR must specify a location of a monero source tree")
endif()

include(FetchContent)
FetchContent_Declare(monero SOURCE_DIR ${MONERO_SOURCE_DIR})

if (NOT monero_POPULATED)
  FetchContent_MakeAvailable(monero)
endif ()

#
# Dependencies specific to lwsf
#

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(Boost_NO_BOOST_CMAKE ON)
if(STATIC)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
endif()
find_package(Boost 1.66 QUIET REQUIRED COMPONENTS program_options thread)

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
    "${MONERO_SOURCE_DIR}/external/easylogging++"
    "${MONERO_SOURCE_DIR}/external/rapidjson/include"
    "${MONERO_SOURCE_DIR}/external/supercop/include"
    "${MONERO_SOURCE_DIR}/src"
)
set_property(TARGET monero::libraries PROPERTY
  INTERFACE_LINK_LIBRARIES
    common
    epee
    mnemonics
    qrcodegen
    wallet_api
)

add_subdirectory(src)

