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
#include <vector>
#include "wallet/api/wallet2_api.h" // monero/src

namespace lwsf { namespace internal
{
  namespace backend { struct wallet; }

  class subaddress_minor final : public ::Monero::Subaddress
  {
    const std::shared_ptr<backend::wallet> data_;
    std::vector<Monero::SubaddressRow*> rows_;

  public:

    explicit subaddress_minor(std::shared_ptr<backend::wallet> data);

    subaddress_minor(const subaddress_minor&) = delete;
    subaddress_minor(subaddress_minor&&) = delete;    
    virtual ~subaddress_minor() override;
    subaddress_minor& operator=(const subaddress_minor&) = delete;
    subaddress_minor& operator=(subaddress_minor&&) = delete;

    void refresh(uint32_t accountIndex) override;
    std::vector<Monero::SubaddressRow*> getAll() const override { return rows_; }
    void addRow(uint32_t accountIndex, const std::string &label) override;
    void setLabel(uint32_t accountIndex, uint32_t addressIndex, const std::string &label) override;
  };

}} // lwsf // internal
