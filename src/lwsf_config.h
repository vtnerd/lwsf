// Copyright (c) 2024, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

namespace lwsf { namespace config
{
  struct lookahead
  {
    std::uint32_t major = 0;
    std::uint32_t minor = 0;
  };

  constexpr const std::size_t bulletproof_version = 4;
  constexpr const std::chrono::seconds connect_timeout{5};
  constexpr const std::chrono::seconds daemon_status_cache{10};
  constexpr const std::string_view default_account_name{"Untitled account"};
  constexpr const lookahead default_lookahead{50, 200};
  constexpr const lookahead default_minimal_lookahead{5, 15};
  constexpr const std::string_view default_primary_name{"Primary account"};
  constexpr const std::size_t initial_buffer_size = 1024 * 64; // 64 KiB
  constexpr const std::size_t max_inputs_in_rpc = 512;
  constexpr const std::size_t max_outputs_in_construction = 16;
  constexpr const std::size_t max_ring_size_in_rpc = 128;
  constexpr const std::size_t max_txes_in_rpc = 2048;
  constexpr const std::size_t min_outputs = 2;
  constexpr const std::uint32_t mixin_default = 15;
  constexpr const std::chrono::seconds refresh_interval{30};
  constexpr const std::chrono::seconds refresh_interval_min{5};
  constexpr const std::chrono::seconds rpc_timeout{5};
}} // lwsf // config
