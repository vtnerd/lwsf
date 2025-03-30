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

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "lws_frontend.h"
#include "wallet/api/wallet2_api.h" // monero/src

namespace lwsf { namespace internal {
  namespace backend { struct wallet; }

  class address_book final : public ::Monero::AddressBook
  {
    const std::shared_ptr<backend::wallet> data_;
    std::vector<Monero::AddressBookRow*> addresses_;
    std::string error_string_;
    ErrorCode error_;

    void clear_status();

  public:

    explicit address_book(std::shared_ptr<backend::wallet> data);

    address_book(const address_book&) = delete;
    address_book(address_book&&) = delete;
    virtual ~address_book() override;
    address_book& operator=(const address_book&) = delete;
    address_book& operator=(address_book&&) = delete;

    virtual std::vector<Monero::AddressBookRow*> getAll() const override { return addresses_; }
    virtual bool addRow(const std::string &dst_addr , const std::string &payment_id, const std::string &description) override; 
    virtual bool deleteRow(std::size_t rowId) override;
    virtual bool setDescription(std::size_t index, const std::string &description) override;
    virtual void refresh() override;
    virtual std::string errorString() const override { return error_string_; }
    virtual int errorCode() const override { return error_; }
    virtual int lookupPaymentID(const std::string &payment_id) const override;

  };
}} // lwsf // internal
