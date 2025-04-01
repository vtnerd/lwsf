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

#include "subaddress_minor.h"

#include <boost/thread/lock_guard.hpp>
#include <ctime>
#include <utility>
#include "backend.h"
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src

namespace lwsf { namespace internal
{
  namespace
  {
    void free_rows(std::vector<Monero::SubaddressRow*>& rows) noexcept
    {
      for (auto row : rows)
        delete row;
      rows.clear();
    }
  }

  subaddress_minor::subaddress_minor(std::shared_ptr<backend::wallet> data)
    : data_(std::move(data)), rows_()
  {
    if (!data_)
      throw std::invalid_argument{"lwsf::internal::subaddress_minor cannot be given nullptr"};
  }

  subaddress_minor::~subaddress_minor()
  {
    free_rows(rows_);
  }

  void subaddress_minor::refresh(const std::uint32_t accountIndex)
  {
    try
    {
      free_rows(rows_);
      
      const boost::lock_guard<boost::mutex> lock{data_->sync};
      const auto account = data_->primary.subaccounts.find(accountIndex);
      if (account == data_->primary.subaccounts.end())
        return;

      rows_.reserve(account->second.minor.size());
      for (const auto& minor : account->second.minor)
      {
        rows_.push_back(
          new Monero::SubaddressRow{
            minor.first,
            data_->get_spend_address({accountIndex, minor.first}),
            minor.second.label
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

  void subaddress_minor::addRow(const std::uint32_t accountIndex, const std::string &label)
  {
    /* TODO */
  }

  void subaddress_minor::setLabel(const std::uint32_t accountIndex, const std::uint32_t addressIndex, const std::string &label)
  {
    {
      const boost::lock_guard<boost::mutex> lock{data_->sync};
      data_->primary.subaccounts.at(accountIndex).minor.at(addressIndex).label = label;
    }
    refresh(accountIndex);
  }

  }} // lwsf // internal

