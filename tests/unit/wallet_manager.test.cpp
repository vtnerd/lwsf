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

#include <optional>
#include "lws_frontend.h"

namespace
{
  struct expected
  {
    std::string spend_key;
    std::string view_key;
    std::uint64_t birthday;
    bool encrypted;
  };

  expected test_manager(lest::env& lest_env, Monero::WalletManager& wm, const std::string& seed, const std::string& passphrase)
  {
    const std::unique_ptr<Monero::Wallet> wallet{
      wm.createWalletFromPolyseed("", "", Monero::MAINNET, seed, passphrase)
    };
    EXPECT(bool(wallet));

    bool encrypted{};
    std::uint64_t birthday{};
    std::string actual_seed{};
    EXPECT(wallet->getPolyseed(actual_seed, birthday, encrypted));
    EXPECT(seed == actual_seed);
    EXPECT(!encrypted);

    return {wallet->secretSpendKey(), wallet->secretViewKey(), birthday, encrypted};
  }
}

LWS_CASE("wallet_manager")
{
  const std::unique_ptr<Monero::WalletManager> lwsf_manager{
    lwsf::WalletManagerFactory::getWalletManager()
  };
  const std::unique_ptr<Monero::WalletManager> default_manager{
    Monero::WalletManagerFactory::getWalletManager()
  };

  EXPECT(bool(lwsf_manager));
  EXPECT(bool(default_manager));

  SETUP("random polyseed")
  {
    std::string seed{};
    std::string error{};
    EXPECT(Monero::Wallet::createPolyseed(seed, error));
    EXPECT(error.empty());
    EXPECT(!seed.empty());

    const auto run_managers = [&] (const std::string passphrase = "") -> expected
    {
      const expected default_result = test_manager(lest_env, *default_manager, seed, passphrase);
      const expected lwsf_result = test_manager(lest_env, *lwsf_manager, seed, passphrase);

      EXPECT(default_result.encrypted == lwsf_result.encrypted);
      EXPECT(default_result.birthday == lwsf_result.birthday);
      EXPECT(default_result.spend_key == lwsf_result.spend_key);
      EXPECT(default_result.view_key == lwsf_result.view_key);
      return default_result;
    };

    SECTION("Compare to default")
    {
      const expected base = run_managers();
      const expected crypted = run_managers("foo");

      EXPECT(base.spend_key != crypted.spend_key);
      EXPECT(base.view_key != crypted.view_key);
      EXPECT(base.birthday == crypted.birthday);
      EXPECT(base.encrypted == crypted.encrypted);
    }
  }
}

