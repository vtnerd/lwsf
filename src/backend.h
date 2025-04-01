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
#include <map>
#include <memory>
#include <optional>
#include <type_traits>
#include <variant>
#include <vector>

#include "byte_slice.h"        // monero/contrib/epee/include
#include "common/expect.h"     // moneor/src
#include "crypto/crypto.h"     // monero/src
#include "crypto/hash.h"       // monero/src
#include "cryptonote_config.h" // monero/src
#include "net/http_client.h"   // monero/contrib/epee/include
#include "ringct/rctTypes.h"   // monero/src
#include "rpc.h"
#include "wallet/api/wallet2_api.h" // monero/src
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

  struct address_book_entry
  {
    std::string address;
    std::string payment_id;
    std::string description;
  };
  WIRE_DECLARE_OBJECT(address_book_entry);

  struct subaddress
  {
    std::string label;
  };
  WIRE_DECLARE_OBJECT(subaddress);

  struct sub_account
  {
    boost::container::flat_map<std::uint32_t, subaddress> minor;
  };
  WIRE_DECLARE_OBJECT(sub_account);

  struct transfer_out
  {
    std::string address;
    std::uint64_t amount;
    rpc::address_meta sender;
    std::optional<crypto::secret_key> secret;
    crypto::public_key tx_pub;
    crypto::public_key output_pub;

    transfer_out()
      : address(), amount(0), sender{}, secret(), tx_pub{}, output_pub{}
    {}
  };
  WIRE_DECLARE_OBJECT(transfer_out);

  struct transfer_in
 {
    std::uint64_t global_index;
    std::uint64_t amount;
    rpc::address_meta recipient;
    std::uint16_t index;
    std::optional<rct::key> rct_mask;
    crypto::public_key tx_pub;

    transfer_in()
      : global_index(0),
        amount(0),
        recipient{},
        index(0),
        rct_mask(),
        tx_pub{}
    {}
  };
  WIRE_DECLARE_OBJECT(transfer_in);

  struct transaction
  {
    transaction()
      : spends(),
        receives(),
        description(),
        timestamp(),
        amount(0),
        fee(0),
        height(),
        unlock_time(0),
        direction(Monero::TransactionInfo::Direction_Out),
        payment_id(),
        id{},
        prefix{},
        coinbase(false)
    {}

    transaction(transaction&&) = default;
    transaction(const transaction&) = default;
    transaction& operator=(transaction&&) = default;
    transaction& operator=(const transaction&) = default;

    bool is_unlocked(std::uint64_t chain_height, Monero::NetworkType type) const;

    /*! flat_map is used here for faster copies/merging. A single allocation
      is needed in the copy (done every refresh interval), instead of an
      allocation per key. */
    boost::container::flat_map<crypto::key_image, transfer_out, memory> spends;
    boost::container::flat_map<crypto::public_key, transfer_in, memory> receives; //!< Key is output pub
    std::string description;
    std::optional<std::time_t> timestamp;
    std::uint64_t amount;
    std::uint64_t fee;
    std::optional<std::uint64_t> height;
    std::uint64_t unlock_time;
    Monero::TransactionInfo::Direction direction;
    std::variant<rpc::empty, crypto::hash8, crypto::hash> payment_id;
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
    std::string language;
    std::vector<address_book_entry> addressbook;
    std::map<std::uint32_t, sub_account> subaccounts;
    boost::container::flat_map<crypto::hash, std::shared_ptr<transaction>, memory> txes;
    std::map<std::string, std::string> attributes;
    std::uint64_t scan_height;
    std::uint64_t restore_height;
    Monero::NetworkType type;
    keypair view;
    keypair spend;
    bool generated_locally;
  };
  WIRE_DECLARE_OBJECT(account);

  struct wallet
  {
    Monero::WalletListener* listener;
    rpc::http_client client;
    account primary;
    std::atomic<std::chrono::steady_clock::time_point::duration::rep> last_sync;
    std::uint64_t blockchain_height;
    std::uint64_t per_byte_fee;
    std::uint64_t fee_mask;
    mutable boost::mutex sync;
    boost::mutex sync_listener;

    wallet();

    cryptonote::network_type get_net_type() const;
    crypto::public_key get_spend_public(const rpc::address_meta& index) const;
    std::string get_spend_address(const rpc::address_meta& index) const;

    //! Serializate `this` wallet to msgpack. Locks contents.
    expect<epee::byte_slice> to_bytes() const;

    //! De-serialize `this` from msgpack. Locks+replaces contents.
    std::error_code from_bytes(epee::byte_slice source);

    //! Attempt
    std::error_code login();

    //! Refreshes txes information. Strong exception guarantee. Locks contents.
    std::error_code refresh(bool mandatory = false);

    std::error_code add_subaccount(std::string label);

    std::error_code restore_height(const std::uint64_t height);

    std::error_code send_tx(epee::byte_slice tx_bytes);
  };
}}} // lwsf // internal // backend
