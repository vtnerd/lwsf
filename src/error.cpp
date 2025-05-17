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
    case error::approval:
      return "Account needs approval on light-wallet-server";
    case error::configuration:
      return "Configuration issue";
    case error::create:
      return "Account creation not possible";
    case error::import_fee:
      return "Import/restore from height needs payment, see address book";
    case error::import_invalid:
      return "Import/restore from height failed due to invalid fee";
    case error::import_pending:
      return "Import/restore from height is awaiting approval";
    case error::network_type:
      return "Mismatch on network type";
    case error::subaddr_ahead:
      return "server has limits too low for requested subaddress lookahead";
    case error::subaddr_disabled:
      return "server has subaddresses disabled";
    case error::subaddr_local:
      return "lwsf (local) limits on subaddresses too small";
<<<<<<< Updated upstream
=======
    case error::tx_critical:
      return "Tx construction had critical error";
    case error::tx_decoys:
      return "Tx construction failed due to invalid decoy response";
    case error::tx_extra:
      return "Tx construction failed to generate tx extra";
    case error::tx_failed:
      return "Tx construction failed (construct_tx failure)";
    case error::tx_invalid_address:
      return "Tx construction was given invalid address";
    case error::tx_long_pid:
      return "Tx construction requested with deprecated long payment id";
    case error::tx_low_funds:
      return  "Tx construction failed due to insufficient funds";
    case error::tx_size_mismatch:
      return "Tx construction requested with amount and destination mismatch";
    case error::tx_sweep:
      return "Tx construction sweep with multiple destinations";
    case error::tx_two_pid:
      return "Tx construction given two payment ids";
>>>>>>> Stashed changes
    case error::unexpected_userinfo:
      return "Unexpected user+pass field in URL";

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
