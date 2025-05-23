// Copyright (c) 2024, The Monero Project
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

#include "transaction_info.h"

#include <boost/container/throw_exception.hpp>
#include <boost/version.hpp>
#include "hex.h"

namespace
{  
  struct payment_id_to_hex
  {
    template<typename T>
    std::string operator()(const T& source) const
    {
      return epee::to_hex::string(epee::as_byte_span(source));
    }

    std::string operator()(const lwsf::internal::rpc::empty&) const { return {}; }
  };
}

namespace lwsf { namespace internal
{
  void transaction_info::update_transfers()
  {
    transfers_.clear();
    transfers_.reserve(data_->transfers.size());
    for (const auto& out : data_->transfers)
      transfers_.emplace_back(out.amount, out.address);
  }

  transaction_info::transaction_info(std::shared_ptr<backend::wallet> wallet, std::shared_ptr<const backend::transaction> data)
    : wallet_(std::move(wallet)), data_(std::move(data)), transfers_()
  {
    if (!wallet_ || !data_)
      throw std::invalid_argument{"lwsf::internal::transaction_info cannot be given nullptr"};
    update_transfers();
  }

  transaction_info::~transaction_info()
  {}

  void transaction_info::update(std::shared_ptr<const backend::transaction> data)
  {
    if (!data)
      throw std::invalid_argument{"lwsf::internal::transaction_info::update cannot be given nullptr"};
    data_ = std::move(data);
    update_transfers();
  }

  std::uint64_t transaction_info::blockHeight() const
  {
    if (data_->height)
      return *data_->height;
    if (isFailed())
      return 0;
    return std::numeric_limits<std::uint64_t>::max();
  }

  std::string transaction_info::description() const
  {
    const boost::lock_guard<boost::mutex> lock{wallet_->sync};
    return data_->description; // this can change outside of refresh func
  }

  std::set<std::uint32_t> transaction_info::subaddrIndex() const
  {
    std::set<std::uint32_t> out;
    const std::uint32_t major = subaddrAccount();

    if (direction() == Direction_In)
    {
      for (const auto& receive : data_->receives)
        out.insert(receive.second.recipient.min_i);
    }
    else
    {
      for (const auto& spend : data_->spends)
        out.insert(spend.second.sender.min_i);
    }

    return out;
  }

  std::uint32_t transaction_info::subaddrAccount() const
  {
    if (data_->direction == Direction_In)
    {
      if (!data_->receives.empty())
        return  data_->receives.begin()->second.recipient.maj_i;
    }
    else if (!data_->spends.empty())
      return data_->spends.begin()->second.sender.maj_i;
    return 0;
  }

  std::string transaction_info::label() const
  {
    const auto get_label = [this] (const rpc::address_meta& meta) -> std::string
    {
      const boost::lock_guard<boost::mutex> lock{wallet_->sync};
      if (meta.maj_i < wallet_->primary.subaccounts.size())
      {
        const auto& major = wallet_->primary.subaccounts.at(meta.maj_i);
        const auto minor = major.detail.find(meta.min_i);
        if (minor != major.detail.end())
          return minor->second.label;
      }
      return {};
    };

    if (data_->direction == Direction_In)
    {
      if (!data_->receives.empty())
        return get_label(data_->receives.begin()->second.recipient);
    }
    else if (!data_->spends.empty())
      return get_label(data_->spends.begin()->second.sender);

    return {};
  }

  uint64_t transaction_info::confirmations() const
  {
    if (!data_->height)
      return 0;
    const boost::lock_guard<boost::mutex> lock{wallet_->sync};
    return std::max(wallet_->blockchain_height, *data_->height) - *data_->height + 1;
  }

  std::string transaction_info::hash() const
  {
    return epee::to_hex::string(epee::as_byte_span(data_->id));
  }

  std::time_t transaction_info::timestamp() const 
  {
    if (data_->timestamp)
      return std::chrono::system_clock::to_time_t(*data_->timestamp);
    if (isFailed())
      return std::numeric_limits<std::time_t>::min();
    return std::numeric_limits<std::time_t>::max();
  }

  std::string transaction_info::paymentId() const
  {
    return std::visit(payment_id_to_hex{}, data_->payment_id);
  }
}} // lwsf // internal
