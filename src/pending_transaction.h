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

#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include "cryptonote_basic/cryptonote_basic.h" // monero/src
#include "wallet/api/wallet2_api.h"            // moneor/src

namespace lwsf { namespace internal
{
  namespace backend { struct wallet; }

  class pending_transaction final : public Monero::PendingTransaction
  {
    const std::shared_ptr<backend::wallet> wallet_; 
    const cryptonote::transaction source_;
    std::error_code error_;
    const Priority priority_;

  public:
    pending_transaction(std::shared_ptr<backend::wallet> wallet, cryptonote::transaction&& source, Priority priority); 

    pending_transaction(pending_transaction&&) = delete;
    pending_transaction(const pending_transaction&) = delete;

    virtual ~pending_transaction() override final;

    pending_transaction& operator=(pending_transaction&&) = delete;
    pending_transaction& operator=(const pending_transaction&) = delete;

    virtual int status() const override final { return priority_; }
    virtual std::string errorString() const override final;
    virtual bool commit(const std::string &filename = "", bool overwrite = false) override final;
    virtual std::uint64_t amount() const = 0;
    virtual std::uint64_t dust() const override final { return 0; }
    virtual std::uint64_t fee() const override final;
    virtual std::vector<std::string> txid() const override final;
    virtual std::uint64_t txCount() const override final { return 1; }
    virtual std::vector<uint32_t> subaddrAccount() const = 0;
    virtual std::vector<std::set<uint32_t>> subaddrIndices() const = 0;

    /**
     * @brief multisigSignData
     * @return encoded multisig transaction with signers' keys.
     *         Transfer this data to another wallet participant to sign it.
     *         Assumed use case is:
     *         1. Initiator:
     *              auto data = pendingTransaction->multisigSignData();
     *         2. Signer1:
     *              pendingTransaction = wallet->restoreMultisigTransaction(data);
     *              pendingTransaction->signMultisigTx();
     *              auto signed = pendingTransaction->multisigSignData();
     *         3. Signer2:
     *              pendingTransaction = wallet->restoreMultisigTransaction(signed);
     *              pendingTransaction->signMultisigTx();
     *              pendingTransaction->commit();
     */
    virtual std::string multisigSignData() = 0;
    virtual void signMultisigTx() = 0;
    /**
     * @brief signersKeys
     * @return vector of base58-encoded signers' public keys
     */
    virtual std::vector<std::string> signersKeys() const = 0;
  };
}} // lwsf // internal
