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

#include "subaddress_account.h"

#include "backend.h"

#include <boost/thread/lock_guard.hpp>
#include <ctime>
#include <utility>
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "error.h"

namespace lwsf { namespace internal
{
  namespace
  {
    struct balance
    {
      std::uint64_t unlocked;
      std::uint64_t total;

      constexpr balance() noexcept
        : unlocked(0), total(0)
      {}
    };

    template<typename T, typename value_type = typename T::value_type>
    std::vector<value_type> copy(const T& src)
    {
      std::vector<value_type> out;
      out.reserve(src.size());
      for (const auto& elem : src)
        out.push_back(elem);
      return out;
    }

    void free_rows(std::vector<Monero::SubaddressAccountRow*>& rows) noexcept
    {
      for (auto row : rows)
        delete row;
      rows.clear();
    }
  }

  subaddress_account::subaddress_account(internal::wallet* wal, const net::wallet_io& data)
    : wal_(wal), data_(data), rows_()
  {
    LWSF_VERIFY(wal_ && data_.wallet);
  }

  subaddress_account::~subaddress_account()
  {
    free_rows(rows_);
  }

  void subaddress_account::addRow(const std::string &label)
  {
    // do not call `data_` function directly, put API requests onto work thread
    wal_->addSubaddressAccount(label);
    refresh();
  }

  void subaddress_account::setLabel(uint32_t accountIndex, const std::string &label)
  {
    {
      const boost::lock_guard<boost::mutex> lock{data_.wallet->sync};
      data_.wallet->primary.subaccounts.at(accountIndex).detail.try_emplace(0).first->second.label = label;
    }
    refresh();
  }

  void subaddress_account::refresh()
  {
    try
    {
      free_rows(rows_);
      std::unordered_map<std::uint32_t, balance> balances;

      const boost::lock_guard<boost::mutex> lock{data_.wallet->sync};
      const Monero::NetworkType net_type = data_.wallet->primary.type;
      const std::uint32_t chain_height = data_.wallet->blockchain_height;

      for (const auto& tx : data_.wallet->primary.txes)
      {
        if (tx.second->failed)
          continue;

        const bool unlocked = tx.second->is_unlocked(chain_height, net_type);
        for (const auto& receive : tx.second->receives)
        {
          auto& balance = balances[receive.second.recipient.maj_i];
          balance.total += receive.second.amount;
          if (unlocked)
            balance.unlocked += receive.second.amount;
        }

        for (const auto& spend : tx.second->spends)
        {
          auto& balance = balances[spend.second.sender.maj_i];
          balance.unlocked -= spend.second.amount;
          balance.total -= spend.second.amount;
        }
      }

      static constexpr const std::uint32_t max_index =
        std::numeric_limits<std::uint32_t>::max();

      const auto& accts = data_.wallet->primary.subaccounts;
      rows_.reserve(accts.size());
      for (std::size_t i = 0; i < accts.size() && i <= max_index; ++i)
      {
        const auto& balance = balances[i];
        rows_.push_back(
          new Monero::SubaddressAccountRow{
            std::uint32_t(i),
            data_.wallet->get_spend_address({std::uint32_t(i), 0}),
            std::string{accts.at(i).primary_label()},
            cryptonote::print_money(balance.total),
            cryptonote::print_money(balance.unlocked)
          }
        );
      }
    }
    catch (...)
    {
      free_rows(rows_);
      throw;
    }
  }
}} // lwsf // internal

