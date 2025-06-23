# Copyright (c) 2024, The Monero Project
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

include_directories(.)
add_subdirectory(wire)

set(lwsf_sources
  address_book.cpp
  backend.cpp
  error.cpp
  pending_transaction.cpp
  rpc.cpp
  subaddress_account.cpp
  subaddress_minor.cpp
  transaction_history.cpp
  transaction_info.cpp
  utils/encrypted_file.cpp
  wallet.cpp
  wallet_manager.cpp
)
set(lwsf_headers
  backend.h
  error.h
  lwsf_config.h
  pending_transaction.h
  rpc.h
  transaction_history.h
  transaction_info.h
  utils/encrypted_file.h
  utils/numeric.h
  wallet.h
)

add_library(lwsf-api ${lwsf_sources} ${lwsf_headers})
target_include_directories(lwsf-api
  PUBLIC
    "${lwsf_SOURCE_DIR}/include"
  PRIVATE
    "."
)
target_link_libraries(lwsf-api
  PUBLIC
    monero::libraries
  PRIVATE
    lwsf-wire
    lwsf-wire-json
    lwsf-wire-msgpack
    lwsf-wire-wrapper
    ${Boost_THREAD_LIBRARY}
    ${sodium_LIBRARY_RELEASE}
    Threads::Threads
)

add_executable(lwsf-ledger ledger_main.cpp)
target_link_libraries(lwsf-ledger
  PRIVATE
    lwsf-api
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
)

