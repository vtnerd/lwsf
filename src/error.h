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

#pragma once

#include <system_error>

namespace lwsf
{
  enum class error : int
  {
    none = 0,           //!< Must be zero for `expect<..>`
    connect_failure,    //!< Connection to server failed
    crypto_failure,     //!< Failure in crypto
    invalid_encoding,   //!< Invalid percent encoding
    invalid_scheme,     //!< Invalid network scheme
    read_failure,       //!< Failed to read file
    rpc_failure,        //!< RPC failed
    unexpected_userinfo,//!< Unexpected user+pass provided
    unsupported_format, //!< File format could not be unpacked
    write_failure       //!< Failed to write file
  };

  //! \return Error message string.
  const char* get_string(error value) noexcept;

  //! \return Category for `schema_error`.
  const std::error_category& error_category() noexcept;

  //! \return Error code with `value` and `schema_category()`.
  inline std::error_code make_error_code(const error value) noexcept
  {
    return std::error_code{int(value), error_category()};
  }

} // lwsf

namespace std
{
  template<>
  struct is_error_code_enum<lwsf::error>
    : true_type
  {};
}
