// Copyright (c) 2024, The Monero Project
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

#include "error.h"

namespace lwsf
{
  const char* get_string(const error value) noexcept
  {
    switch (value)
    {
    case error::none:
      return "No error";
    case error::configuration:
      return "Configuration issue";
    case error::connect_failure:
      return "Connection to server failed";
    case error::crypto_failure:
      return "Cryptography issue";
    case error::invalid_encoding:
      return "File had invalid encoding";
    case error::invalid_scheme:
      return "Invalid URL scheme";
    case error::read_failure:
      return "Failed to read file";
    case error::rpc_failure:
      return "RPC failed";
    case error::unexpected_userinfo:
      return "Unexpected user+pass field in URL";
    case error::unsupported_format:
      return "Could not unpack file";
    case error::write_failure:
      return "Failed to write file";

    default:
      break;
    }
    return "Unknown wallet error";
  }

  const std::error_category& error_category() noexcept
  {
    struct category final : std::error_category
    {
      virtual const char* name() const noexcept override final
        {
          return "lws::error_category()";
        }

        virtual std::string message(int value) const override final
        {
          return get_string(error(value));
        }
    };
    static const category instance{};
    return instance;
  }
} // lwsf
