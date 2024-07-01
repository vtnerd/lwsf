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

    std::string operator()(const std::nullptr_t) const { return {}; }
  };
}

namespace lwsf { namespace internal
{
  transaction_info::transaction_info(std::shared_ptr<backend::wallet> wallet, std::shared_ptr<backend::transaction> data)
    : wallet_(std::move(wallet)), data_(std::move(data)), transfers_()
  {
    if (!wallet_ || !data_)
      throw std::logic_error{"internal::transaction_info cannot be given nullptr"};

    transfers_.reserve(data_->spends.size());
    for (const auto& spend : data_->spends)
      transfers_.emplace_back(spend.amount, spend.address);
  }

  transaction_info::~transaction_info()
  {}

  uint64_t transaction_info::confirmations() const
  {
    const auto block_height = blockHeight();
    const boost::lock_guard<boost::mutex> lock{wallet_->sync};
    return std::max(wallet_->blockchain_height, block_height) - block_height;
  }

  std::string transaction_info::hash() const
  {
    return epee::to_hex::string(epee::as_byte_span(data_->id));
  }

  std::string transaction_info::paymentId() const
  {
    return std::visit(payment_id_to_hex{}, data_->payment_id);
  }
}} // lwsf // internal
