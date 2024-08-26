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

#include "transaction_history.h"

#include <boost/thread/lock_guard.hpp>
#include <limits>
#include <stdexcept>

#include "transaction_info.h"

#include "hex.h" // monero/contrib/epee/include

namespace lwsf { namespace internal
{
  transaction_history::transaction_history(std::shared_ptr<backend::wallet> data)
    : data_(std::move(data))
  {
    if (!data_)
      throw std::logic_error{"transaction_history was given nullptr"};
  }

  transaction_history::~transaction_history()
  {}

  int transaction_history::count() const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (std::numeric_limits<int>::max() < data_->primary.txes.size())
      throw std::runtime_error{"Exceeded max int size in transaction_history::count"};
    return data_->primary.txes.size();
  }

  std::shared_ptr<TransactionInfo> transaction_history::transaction(int index) const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (index < 0 || data_->primary.txes.size() < unsigned(index))
      throw std::runtime_error{"index provided to transaction invalid"};
    return std::make_shared<transaction_info>(data_, data_->primary.txes.nth(unsigned(index))->second);
  }

  std::shared_ptr<TransactionInfo> transaction_history::transaction(const std::string &id) const
  {
    crypto::hash binary_id{};
    if (!epee::from_hex::to_buffer(epee::as_mut_byte_span(binary_id), id))
      throw std::runtime_error{"transaction_history given invalid hex id"};

    const boost::lock_guard<boost::mutex> lock{data_->sync};   
    const auto iter = data_->primary.txes.find(binary_id);
    if (iter != data_->primary.txes.end())
      return std::make_shared<transaction_info>(data_, iter->second);
    return nullptr;
  }

  std::vector<std::shared_ptr<TransactionInfo>> transaction_history::getAll() const
  {
    std::vector<std::shared_ptr<TransactionInfo>> out;
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    out.reserve(data_->primary.txes.size());
    for (const auto& tx : data_->primary.txes)
      out.push_back(std::make_shared<transaction_info>(data_, tx.second));
    return out;
  }

  void transaction_history::refresh()
  {
    data_->refresh(true);
  } 

  void transaction_history::setTxNote(const std::string &txid, const std::string &note)
  { 
    crypto::hash binary_id{};
    if (!epee::string_tools::hex_to_pod(txid, binary_id))
      throw std::runtime_error{"transaction_history given invalid hex id"};

    const boost::lock_guard<boost::mutex> lock{data_->sync};
    auto iter = data_->primary.txes.find(binary_id);
    if (iter == data_->primary.txes.end())
      throw std::runtime_error{"transaction_history setTxNote given invalid id"};

    iter->second->description = note;
  }
}} // lwsf // internal
