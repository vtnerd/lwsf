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

#pragma once

#include <memory>
#include <unordered_map>
#include <vector>
#include "crypto/hash.h"            // monero/src
#include "wallet/api/wallet2_api.h" // monero/src

namespace lwsf { namespace internal
{
  namespace backend { class wallet; }
  class transaction_history final : public Monero::TransactionHistory
  {
    const std::shared_ptr<backend::wallet> data_;
    std::vector<Monero::TransactionInfo*> txes_;
    mutable std::unordered_map<crypto::hash, std::unique_ptr<Monero::TransactionInfo>> by_id_;

  public:
    explicit transaction_history(std::shared_ptr<backend::wallet> data);

    transaction_history(const transaction_history&) = delete;
    transaction_history(transaction_history&&) = delete;
    virtual ~transaction_history() override;
    transaction_history& operator=(const transaction_history&) = delete;
    transaction_history& operator=(transaction_history&&) = delete;

    virtual int count() const override { return txes_.size(); }
    virtual Monero::TransactionInfo* transaction(int index)  const override;
    virtual Monero::TransactionInfo* transaction(const std::string &id) const override;
    virtual std::vector<Monero::TransactionInfo*> getAll() const override { return txes_; }
    virtual void refresh() override;
    virtual void setTxNote(const std::string &txid, const std::string &note) override;
  };
}} // lwsf // internal
