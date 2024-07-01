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

#include <atomic>
#include <boost/container/flat_map.hpp>
#include <boost/thread/mutex.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <type_traits>
#include <variant>
#include <vector>

#include "common/expect.h"   // moneor/src
#include "crypto/crypto.h"   // monero/src
#include "crypto/hash.h"     // monero/src
#include "lws_frontend.h"
#include "net/http_client.h" // monero/contrib/epee/include
#include "ringct/rctTypes.h" // monero/src
#include "rpc.h"
#include "wire/fwd.h"

namespace lwsf { namespace internal { namespace backend
{
  struct memory
  {
    template<typename T>
    bool operator()(const T& lhs, const T& rhs) const noexcept
    {
      static_assert(std::is_pod<T>::value);
      return std::memcmp(std::addressof(lhs), std::addressof(rhs), sizeof(T)) < 0;
    }
  };

  struct transfer_out
  {
    std::string address;
    std::uint64_t amount;
    rpc::address_meta sender;
    std::optional<crypto::secret_key> secret;
    crypto::public_key tx_pub;

    transfer_out()
      : address(), amount(0), sender(), secret(), tx_pub{}
    {}

    explicit transfer_out(const std::uint64_t amount, const crypto::public_key& tx_pub)
      : address(), amount(amount), sender(), secret(), tx_pub(tx_pub)
    {}
  };
  WIRE_DECLARE_OBJECT(transfer_out);

  struct transfer_in
  {
    std::uint64_t global_index;
    std::uint64_t amount;
    rpc::address_meta recipient;
    std::uint16_t index;
    crypto::public_key output_pub;
    rct::key rct_mask;

    transfer_in();
    explicit transfer_in(const rpc::output& source); 
  };
  WIRE_DECLARE_OBJECT(transfer_in);
  
  struct transaction
  {
    transaction() = delete;
    std::vector<transfer_out> spends;
    std::map<crypto::public_key, transfer_in, memory> receives;
    std::string description;
    std::string label;
    std::optional<std::time_t> timestamp;
    std::uint64_t amount;
    std::uint64_t fee;
    std::optional<std::uint64_t> height;
    std::uint64_t unlock_time;
    TransactionInfo::Direction direction;
    std::variant<std::nullptr_t, crypto::hash8, crypto::hash> payment_id;
    std::optional<crypto::secret_key> tx_secret;
    crypto::public_key pub;
    crypto::hash id;
    crypto::hash prefix;
    bool coinbase;
  };
  WIRE_DECLARE_OBJECT(transaction);

  struct keypair
  {
    keypair() = delete;
    crypto::secret_key sec;
    crypto::public_key pub;
  };
  WIRE_DECLARE_OBJECT(keypair);

  struct account
  {
    account() = delete;
    std::string address; //!> not serialized, recovered on read_bytes
    boost::container::flat_map<crypto::hash, std::shared_ptr<transaction>, memory> txes;
    std::uint64_t restore_height;
    NetworkType type;
    keypair view;
    keypair spend;
  };
  WIRE_DECLARE_OBJECT(account);

  struct wallet
  {
    rpc::http_client client;
    account primary;
    std::error_code status;
    std::atomic<std::chrono::steady_clock::time_point::rep> last_sync;
    std::uint64_t scan_height;
    std::uint64_t blockchain_height;
    mutable boost::mutex sync;
    const bool generated_locally;

    explicit wallet(bool generated_locally);

    expect<epee::byte_slice> to_bytes() const;
    expect<void> from_bytes(epee::byte_slice source);

    bool login() const;
    void refresh(bool mandatory = false);
  };
}}} // lwsf // internal // backend
