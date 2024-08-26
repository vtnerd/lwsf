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

#include "lws_frontend.h"

#include <memory>
#include <string>
#include <vector>

#include "backend.h"

namespace lwsf { namespace internal
{
  //! \todo isFailed, subaddressIndex, and subaddrAccount
  class transaction_info final : public lwsf::TransactionInfo
  {
    const std::shared_ptr<backend::wallet> wallet_;
    const std::shared_ptr<backend::transaction> data_;
    std::vector<Transfer> transfers_;

  public:
    explicit transaction_info(std::shared_ptr<backend::wallet> wallet, std::shared_ptr<backend::transaction> data);

    transaction_info(const transaction_info&) = delete;
    transaction_info(transaction_info&&) = delete;
    virtual ~transaction_info() override;
    transaction_info& operator=(const transaction_info&) = delete;
    transaction_info& operator=(transaction_info&&) = delete;

    virtual Direction direction() const override { return data_->direction; }
    virtual bool isPending() const override { return !data_->height; }
    virtual bool isFailed() const override { return false; }
    virtual bool isCoinbase() const override { return data_->coinbase; }
    virtual uint64_t amount() const override { return data_->amount; }
    virtual uint64_t fee() const override { return data_->fee; }
    virtual uint64_t blockHeight() const override { return data_->height.value_or(0); }
    virtual std::string description() const override;
    virtual std::set<uint32_t> subaddrIndex() const override { return {}; };
    virtual uint32_t subaddrAccount() const override { return 0; }
    virtual std::string label() const override { return data_->label; }
    virtual uint64_t confirmations() const override;
    virtual uint64_t unlockTime() const override { return data_->unlock_time; }
    virtual std::string hash() const override;
    virtual std::time_t timestamp() const override { return data_->timestamp.value_or(std::time_t(0)); }
    virtual std::string paymentId() const override;
    virtual const std::vector<Transfer>& transfers() const override { return transfers_; }
  };
}} // lwsf // internal
