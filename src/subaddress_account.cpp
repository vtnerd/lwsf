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

#include <boost/thread/lock_guard.hpp>
#include <ctime>
#include <utility>
#include "backend.h"
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src

namespace lwsf { namespace internal
{
  namespace
  {
    struct balance
    {
      std::uint64_t unlocked;
      std::uint64_t total;

      balance()
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

  subaddress_account::subaddress_account(std::shared_ptr<backend::wallet> data)
    : data_(std::move(data)), rows_()
  {
    if (!data_)
      throw std::invalid_argument{"lwsf::internal::subaddress_account cannot be given nullptr"};
  }

  subaddress_account::~subaddress_account()
  {
    free_rows(rows_);
  }

  void subaddress_account::addRow(const std::string &label)
  {
    data_->add_subaccount(label);
    refresh();
  }

  void subaddress_account::setLabel(uint32_t accountIndex, const std::string &label)
  {
    {
      const boost::lock_guard<boost::mutex> lock{data_->sync};
      data_->primary.subaccounts.at(accountIndex).minor.at(0).label = label;
    }
    refresh();
  }

  void subaddress_account::refresh()
  {
    try
    {
      free_rows(rows_);
      std::unordered_map<std::uint32_t, balance> balances;

      const boost::lock_guard<boost::mutex> lock{data_->sync};
      const Monero::NetworkType net_type = data_->primary.type;
      const std::uint32_t chain_height = data_->blockchain_height;

      for (const auto& tx : data_->primary.txes)
      {
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

      rows_.reserve(data_->primary.subaccounts.size());
      for (const auto& sub : data_->primary.subaccounts)
      {
        const auto& balance = balances[sub.first];
        rows_.push_back(
          new Monero::SubaddressAccountRow{
            sub.first,
            data_->get_spend_address({sub.first, 0}),
            sub.second.minor.empty() ? "" : sub.second.minor.begin()->second.label,
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

