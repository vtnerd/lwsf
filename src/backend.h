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
#include <unordered_map>
#include <type_traits>
#include <variant>
#include <vector>

#include "byte_slice.h"        // monero/contrib/epee/include
#include "common/expect.h"     // moneor/src
#include "crypto/crypto.h"     // monero/src
#include "crypto/hash.h"       // monero/src
#include "cryptonote_config.h" // monero/src
#include "cryptonote_basic/account.h" // monero/src
#include "lwsf_config.h"
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

    subaddress()
      : label()
    {}

    explicit subaddress(const std::string_view label)
      : subaddress(std::string{label})
    {}

    explicit subaddress(std::string label)
      : label(std::move(label))
    {}
  };
  WIRE_DECLARE_OBJECT(subaddress);

  struct sub_account
  {
    boost::container::flat_map<std::uint32_t, subaddress> detail; //!< Minor address info
    std::uint32_t last; //!< Last minor index in use (inclusive)
    std::uint32_t server_lookahead; //!< Status of server (minor) lookahead. Inclusive

    //! Creates 1 subaddress entry (key == `0`) with default label
    sub_account();

    //! \return Label for `minor`, if one was set. 
    std::string_view sub_label(std::uint32_t minor) const noexcept;

    //! \return Primary label for account (`minor == 0` is "special").
    std::string_view primary_label() const noexcept;
  };
  WIRE_DECLARE_OBJECT(sub_account);

  struct transfer_spend
  {
    std::uint64_t amount;
    rpc::address_meta sender;
    crypto::public_key tx_pub;
    crypto::public_key output_pub;

    transfer_spend() noexcept
      : amount(0), sender{}, tx_pub{}, output_pub{}
    {}
  };
  WIRE_DECLARE_OBJECT(transfer_spend);

  struct transfer_in
 {
    std::uint64_t global_index;
    std::uint64_t amount;
    rpc::address_meta recipient;
    std::uint16_t index;
    std::optional<rct::key> rct_mask;
    crypto::public_key tx_pub;

    transfer_in() noexcept
      : global_index(0),
        amount(0),
        recipient{},
        index(0),
        rct_mask(),
        tx_pub{}
    {}
  };
  WIRE_DECLARE_OBJECT(transfer_in);

  struct transfer_out
  {
    std::string address;
    std::uint64_t amount;
    crypto::secret_key secret;

    transfer_out()
      : address(), amount(0), secret{}
    {}

    transfer_out(std::string address, const std::uint64_t amount)
      : address(std::move(address)), amount(amount), secret{}
    {}
  };
  WIRE_DECLARE_OBJECT(transfer_out);

  struct transaction
  {
    transaction();
    
    transaction(transaction&&) = default;
    transaction(const transaction& rhs);
    transaction& operator=(transaction&&) = default;

    bool is_unlocked(std::uint64_t chain_height, Monero::NetworkType type) const;

    /*! flat_map is used here for faster copies/merging. A single allocation
      is needed in the copy (done every refresh interval), instead of an
      allocation per key. */
    epee::byte_slice raw_bytes; // for sends held for 100 confirmations
    boost::container::flat_map<crypto::key_image, transfer_spend, memory> spends;
    boost::container::flat_map<crypto::public_key, transfer_in, memory> receives; //!< Key is output pub
    std::vector<transfer_out> transfers;
    std::string description;
    std::optional<std::chrono::system_clock::time_point> timestamp; //!< guaranteed to be unix epoch in C++20
    std::optional<std::uint64_t> height;
    std::uint64_t amount;
    std::uint64_t fee;
    std::uint64_t unlock_time;
    Monero::TransactionInfo::Direction direction;
    std::variant<rpc::empty, crypto::hash8, crypto::hash> payment_id;
    crypto::hash id;
    crypto::hash prefix;
    bool coinbase;
    bool failed;
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

    std::string address; //!< not serialized, recovered on read_bytes
    std::string language;
    std::vector<address_book_entry> addressbook;
    std::vector<sub_account> subaccounts; //! Enabled major subaccounts. Index indicates `sub.major` value.
    std::unordered_map<crypto::hash, std::shared_ptr<transaction>> txes;
    std::unordered_map<std::string, std::string> attributes;
    std::uint64_t scan_height;    //!< last block scanned
    std::uint64_t restore_height; //!< aka scan start height
    std::uint64_t requested_start = std::numeric_limits<std::uint64_t>::max(); 
    config::lookahead lookahead = config::default_lookahead; //<! Lookahead as requested by user
    Monero::NetworkType type;
    keypair view;
    keypair spend;
    bool generated_locally; //!< True iff wallet was generated and not recovered
  };
  WIRE_DECLARE_OBJECT(account);

  //! All functions should provide the strong-exception guarantee
  struct wallet
  {
    Monero::WalletListener* listener;
    rpc::http_client client;
    account primary;
    std::vector<std::uint64_t> per_byte_fee; //!< by priority level
    std::error_code refresh_error; //!< Cached because `refresh(...)` is rate limited
    std::error_code lookahead_error; //!< warnings/errors of `server_lookahead` value
    std::error_code import_error; //!< Error from `import_wallet_request`
    std::chrono::steady_clock::time_point last_sync;
    std::uint64_t blockchain_height;
    std::uint64_t fee_mask;
    std::uint32_t server_lookahead; //!< Status of major lookahead server-side. Inclusive
    mutable boost::mutex sync;
    boost::mutex sync_listener;
    boost::mutex sync_refresh;
    bool passed_login;

    wallet();

    // `sync` mutex is NOT acquired for this group

    cryptonote::network_type get_net_type() const;
    crypto::public_key get_spend_public(const rpc::address_meta& index) const;
    cryptonote::account_keys get_primary_keys() const;
    cryptonote::account_public_address get_spend_account(const rpc::address_meta& index) const;
    std::string get_spend_address(const rpc::address_meta& index) const;

    // End GROUP

    // `sync` mutex IS acquired for this group (until end). Do not hold this mutex

    //! Serialize `this` wallet to msgpack. Locks contents.
    expect<epee::byte_slice> to_bytes() const;

    //! De-serialize `this` from msgpack. Locks+replaces contents.
    std::error_code from_bytes(epee::byte_slice source);

    /*! Attempt login and sync subaddresses. The result of subaddress syncing,
    including errors, is stored in `server_lookahead`.
    \return No errors if login succeeded. */
    std::error_code login();

    //! Refreshes txes information. Strong exception guarantee.
    std::error_code refresh(bool mandatory = false);

    //! Notify server that new major accounts need to be watched.
    std::error_code register_subaccount(std::uint32_t maj_i);

    //! Notify server that new minor accounts need to be watched.
    std::error_code register_subaddress(std::uint32_t maj_i, std::uint32_t min_i);

    //! Modify local and possibly server lookahead
    std::error_code set_lookahead(std::uint32_t major, std::uint32_t minor);

    std::error_code restore_height(const std::uint64_t height);

    expect<std::vector<rpc::random_outputs>> get_decoys(const rpc::get_random_outs_request& req);
    std::error_code send_tx(epee::byte_slice tx_bytes);
  };
}}} // lwsf // internal // backend
