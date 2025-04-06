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
#include <map>
#include <stdexcept>

#include "backend.h"
#include "transaction_info.h"

#include "hex.h" // monero/contrib/epee/include

namespace lwsf { namespace internal
{
  namespace
  {
    void free_txes(std::vector<Monero::TransactionInfo*>& txes) noexcept
    {
      for (auto tx : txes)
        delete tx;
      txes.clear();
    }
  }

  transaction_history::transaction_history(std::shared_ptr<backend::wallet> data)
    : data_(std::move(data)), txes_(), by_id_()
  {
    if (!data_)
      throw std::invalid_argument{"lwsf::internal::transaction_history cannot be given nullptr"};
  }

  transaction_history::~transaction_history()
  {
    free_txes(txes_);
  }

  Monero::TransactionInfo* transaction_history::transaction(int index) const
  {
    if (index < 0 || txes_.size() <= unsigned(index))
      return nullptr;
    return txes_[index];
  }

  Monero::TransactionInfo* transaction_history::transaction(const std::string &id) const
  {
    crypto::hash binary_id{};
    if (!epee::string_tools::hex_to_pod(id, binary_id))
      return nullptr;

    // hold the lock during the map lookup, this is const and should be thread-safe
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    auto& info = by_id_[binary_id];
    if (!info)
    {
      const auto iter = data_->primary.txes.find(binary_id);
      if (iter == data_->primary.txes.end())
        return nullptr;
      info = std::make_unique<transaction_info>(data_, iter->second);
    }
    return info.get();
  }

  void transaction_history::refresh()
  {
    std::multimap<std::uint64_t, std::shared_ptr<const backend::transaction>> temp;
    {
      const boost::lock_guard<boost::mutex> lock{data_->sync};
      if (std::numeric_limits<int>::max() < data_->primary.txes.size())
        throw std::runtime_error{"lwsf::internal::transaction_history::refresh exceeds max history size"};

      for (const auto& tx : data_->primary.txes)
        temp.emplace(tx.second->height.value_or(std::numeric_limits<std::uint64_t>::max()), tx.second);
    }

    // be careful about exceptions and memory leaks. this should be safe

    for (std::size_t i = temp.size(); i < txes_.size(); ++i)
    {
      const std::unique_ptr<Monero::TransactionInfo> destroy{txes_[i]};
      txes_[i] = nullptr;
    }

    by_id_.clear();
    txes_.resize(temp.size());

    try
    {
      std::size_t i = 0;
      for (auto& backend_tx : temp)
      {
        if (txes_[i])
          static_cast<transaction_info*>(txes_[i])->update(std::move(backend_tx.second));
        else
          txes_[i] = new transaction_info{data_, std::move(backend_tx.second)};
        ++i;
      }
    }
    catch (...)
    {
      free_txes(txes_);
      throw;
    }
  } 

  void transaction_history::setTxNote(const std::string &txid, const std::string &note)
  { 
    crypto::hash binary_id{};
    if (!epee::string_tools::hex_to_pod(txid, binary_id))
      return; 

    const boost::lock_guard<boost::mutex> lock{data_->sync};
    auto iter = data_->primary.txes.find(binary_id);
    if (iter != data_->primary.txes.end())
      iter->second->description = note;
  }
}} // lwsf // internal
