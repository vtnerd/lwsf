// Copyright (c) 2025, The Monero Project
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

#include "framework.test.h"
#include "rpc.h"

LWS_CASE("rpc::subaddrs")
{
  SETUP("empty subaddrs")
  {
    lwsf::internal::rpc::subaddrs subaddr{};
    EXPECT(subaddr.value.empty());
    EXPECT(subaddr.is_valid());  

    SECTION("constructor")
    {
      subaddr = lwsf::internal::rpc::subaddrs{10};
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 1);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 10);
    }

    SECTION("is_valid")
    {
      subaddr.value = {{0, 0}};
      EXPECT(subaddr.is_valid());

      subaddr.value = {{0, 1}, {2, 3}};
      EXPECT(subaddr.is_valid());

      subaddr.value = {{1, 0}};
      EXPECT(!subaddr.is_valid());

      subaddr.value = {{0, 1}, {1, 3}};
      EXPECT(!subaddr.is_valid());
    }

    SECTION("merge from empty")
    {
      subaddr.merge(100);
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 1);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 100);
    }

    SECTION("merge from one item prepend")
    {
      subaddr.value = {{10, 12}};
      subaddr.merge(9);
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 2);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 9);
      EXPECT(std::get<0>(*subaddr.value.nth(1)) == 10);
      EXPECT(std::get<1>(*subaddr.value.nth(1)) == 12);
    }

    SECTION("merge from one item front")
    {
      subaddr.value = {{10, 12}};
      subaddr.merge(10);
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 1);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 12);
    }

    SECTION("merge from one item middle")
    {
      subaddr.value = {{10, 12}};
      subaddr.merge(11);
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 1);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 12);
    }

    SECTION("merge from one item end")
    {
      subaddr.value = {{10, 12}};
      subaddr.merge(12);
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 1);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 12);
    }

    SECTION("merge from two item split directly")
    {
      subaddr.value = {{10, 12}, {14, 15}};
      subaddr.merge(13);
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 2);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 13);
      EXPECT(std::get<0>(*subaddr.value.nth(1)) == 14);
      EXPECT(std::get<1>(*subaddr.value.nth(1)) == 15);
    }

    SECTION("merge from two item split gap")
    {
      subaddr.value = {{10, 12}, {16, 17}};
      subaddr.merge(14);
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 2);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 14);
      EXPECT(std::get<0>(*subaddr.value.nth(1)) == 16);
      EXPECT(std::get<1>(*subaddr.value.nth(1)) == 17);
    }

    SECTION("merge from two item last")
    {
      subaddr.value = {{10, 12}, {14, 15}};
      subaddr.merge(14);
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 1);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 15);
    }

    SECTION("merge from two item append")
    {
      subaddr.value = {{10, 12}, {14, 15}};
      subaddr.merge(16);
      EXPECT(subaddr.is_valid());
      EXPECT(subaddr.value.size() == 1);
      EXPECT(std::get<0>(*subaddr.value.nth(0)) == 0);
      EXPECT(std::get<1>(*subaddr.value.nth(0)) == 16);
    }
  }
}

