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
#include <optional>
#include <string>
#include <vector>
#include "wallet/api/wallet2_api.h" // monero/src

namespace lwsf
{
  std::string displayAmount(std::uint64_t amount);
  Monero::optional<std::uint64_t> amountFromString(const std::string &amount);
  bool addressValid(const std::string &str, Monero::NetworkType nettype);

  std::vector<std::vector<std::uint8_t>> qrcode(Monero::Wallet const* wal, std::uint32_t major, std::uint32_t minor);

  struct WalletManagerFactory
  {
      // logging levels for underlying library
      enum class LogLevel
      {
        Silent = -1,
        L0 = 0,
        L1 = 1,
        L2 = 2,
        L3 = 3,
        L4 = 4,
        Min = Silent,
        Max = L4
      };

      static Monero::WalletManager* getWalletManager();
      static void setLogLevel(LogLevel level);
      static void setLogCategories(const std::string &categories);
  };
} // lwsf
