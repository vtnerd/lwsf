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

#include "pending_transaction.h"

#include <stdexcept>
#include "backend.h"
#include "byte_slice.h"   // monero/contrib/epee/include
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "error.h"
#include "string_tools.h" // monero/contrib/epee/include


namespace lwsf { namespace internal
{
  namespace
  {
    cryptonote::transaction get_tx(expect<cryptonote::transaction>&& source)
    {
      if (source)
        return {std::move(*source)};
      return {};
    }
  }
  pending_transaction::pending_transaction(std::shared_ptr<backend::wallet> wallet, expect<cryptonote::transaction> source, std::shared_ptr<backend::transaction> local)
    : wallet_(std::move(wallet)), error_(source.error()), local_(std::move(local))
  {
    if (!wallet_)
      throw std::invalid_argument{"lwsf::internal::pending_transction cannot be given nullptr backend"};
  }

  pending_transaction::~pending_transaction()
  {}

  int pending_transaction::status() const
  {
    return error_ ? Status_Error : Status_Ok;
  }

  std::string pending_transaction::errorString() const
  {
    if (error_)
      return error_.message();
    return {};
  }

  bool pending_transaction::commit(const std::string &filename, bool)
  {
    // saving to file not yet implemented
    if (error_ || !filename.empty())
      return false;

    if (local_)
      error_ = wallet_->send_tx(local_->raw_bytes.clone());
    else if (!error_)
      error_ = error::tx_failed;

    if (!error_ && local_)
    {
      const boost::lock_guard<boost::mutex> lock{wallet_->sync};
      auto entry = wallet_->primary.txes.try_emplace(local_->id).first;
      if (!entry->second)
        entry->second = local_;
    }

    return !error_;
  }

  std::uint64_t pending_transaction::amount() const
  {
    if (!local_)
      return 0;
    return local_->amount;
  }

  std::uint64_t pending_transaction::fee() const
  { 
    if (!local_)
      return 0;
    return local_->fee;
  }

  std::vector<std::string> pending_transaction::txid() const
  {
    if (!local_)
      return {};
    return {epee::to_hex::string(epee::as_byte_span(local_->id))};
  }
}} // lwsf // internal
