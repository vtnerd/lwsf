// Copyright (c) 2025, The Monero Project
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

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace lwsf { namespace internal
{
  template<typename T>
  class safe_integer
  {
    static_assert(std::is_integral<T>());
    T value_;
  public:
    constexpr safe_integer() noexcept
      : value_(0)
    {}

    constexpr safe_integer(const T value) noexcept
      : value_(value)
    {}

    template<typename U>
    constexpr safe_integer(const U value) noexcept
      : value_(value)
    {
      static_assert(std::is_same<U, void>(), "invalid conversion");
    }

    constexpr safe_integer(const safe_integer&) noexcept = default;
    constexpr safe_integer& operator=(const safe_integer&) noexcept = default;

    constexpr operator T() const noexcept { return value_; }

    template<typename U>
    constexpr operator U() const noexcept
    { static_assert(std::is_same<U, void>(), "invalid conversion"); };

    safe_integer& add(safe_integer rhs)
    {
      if (std::numeric_limits<T>::max() - value_ < rhs.value_)
        throw std::overflow_error{"safe_integer overflow in addition"};
      value_ += rhs.value_;
      return *this;
    }

    safe_integer& subtract(safe_integer rhs)
    {
      if ((0 < rhs.value_ && value_ < std::numeric_limits<T>::min() + rhs.value_) || (rhs.value_ < 0 && value_ > std::numeric_limits<T>::max() + rhs.value_))
        throw std::underflow_error{"safe_integer underflow in subtraction"};
      value_ -= rhs.value_;
      return *this;
    }

    safe_integer& operator+=(safe_integer rhs) { return add(rhs); }
    safe_integer& operator-=(safe_integer rhs) { return subtract(rhs); }
  };

  using safe_uint64_t = safe_integer<std::uint64_t>;
}} // lwsf // internal

