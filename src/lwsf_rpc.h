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

#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include <boost/core/demangle.hpp>
#include <boost/optional/optional.hpp>
#include <boost/thread/locks.hpp>
#include <boost/variant.hpp>
#include <chrono>
#include <ctime>
#include <system_error>
#include <type_traits>
#include <vector>
#include "byte_slice.h"  // monero/contrib/epee/include
#include "byte_stream.h" // moneor/contrib/epee/include
#include "common/expect.h"   // monero/src
#include "crypto/crypto.h"   // monero/src
#include "error.h"
#include "lwsf_config.h"
#include "net/http.h"
#include "ringct/rctTypes.h" // monero/src
#include "wire/basic_value.h"
#include "wire/fwd.h"
#include "wire/json.h"
#include "wire/msgpack/fwd.h"
#include "wire/traits.h"

namespace lwsf { namespace internal { namespace rpc
{
  using max_subaddrs = wire::max_element_count<16384>;
  struct daemon_status;

  template<typename T, typename F>
  struct unpacker
  {
    T* out;
    F f;

    void operator()(std::error_code error, epee::byte_slice response)
    {
      LWSF_VERIFY(out);
      if (!error)
      {
        error = wire::json::from_bytes({reinterpret_cast<const char*>(response.data()), response.size()}, *out);
        if (error)
          MERROR("Failed to unpack " << boost::core::demangle(typeid(T).name()) << ": " << error.message());
      }
      f(error);
    }
  };
  

  /*! `f` may be buffered in `client` (i.e. NOT in ASIO _yet_), and therefore
   callers need to ensure `f` only has `weak_ptr` to object owning `client`. */
  template<typename T, typename U, typename F>
  void invoke_async(const http::client& client, const T& in, U* out, F f)
  {
    // /daemon_status historically needed to be a post
    if constexpr (!std::is_empty<T>{} || std::is_same<U, daemon_status>{})
    {
      epee::byte_stream sink{};
      std::error_code error = wire::json::to_bytes(sink, in);
      if (error)
        return f(error);
      client.post_async(U::endpoint(), epee::byte_slice{std::move(sink)}, unpacker<U, F>{out, std::move(f)});
    }
    else
      client.get_async(U::endpoint(), unpacker<U, F>{out, std::move(f)});
  }

  struct empty {};
  WIRE_DECLARE_OBJECT(empty);

  struct address_meta
  {
    std::uint32_t maj_i;
    std::uint32_t min_i;

    constexpr address_meta() noexcept
      : maj_i(0), min_i(0)
    {}

    constexpr address_meta(const std::uint32_t maj, std::uint32_t min) noexcept
      : maj_i(maj), min_i(min)
    {}

    constexpr address_meta(config::lookahead src) noexcept
      : maj_i(src.major), min_i(src.minor)
    {}

    constexpr bool is_default() const noexcept { return !maj_i && !min_i; }
  };
  WIRE_DECLARE_OBJECT(address_meta);

  inline constexpr bool operator<(const address_meta& lhs, const address_meta& rhs) noexcept
  {
    return lhs.maj_i == rhs.maj_i ?
      lhs.min_i < rhs.min_i : lhs.maj_i < rhs.maj_i;
  }
  inline constexpr bool operator==(const address_meta& lhs, const address_meta& rhs) noexcept
  {
    return lhs.maj_i == rhs.maj_i && lhs.min_i == rhs.min_i;
  }
  inline constexpr bool operator!=(const address_meta& lhs, const address_meta& rhs) noexcept
  {
    return lhs.maj_i != rhs.maj_i || lhs.min_i != rhs.min_i;
  }

 
  struct login
  {
    login() = delete;

    std::string address;
    crypto::secret_key view_key;
  };
  void write_bytes(wire::writer&, const login&);

 
  struct login_request
  {
    login_request() = delete;

    std::string address;
    crypto::secret_key view_key;
    address_meta lookahead;
    bool create_account;
    bool generated_locally;
  };
  void write_bytes(wire::json_writer&, const login_request&);

  struct login_response
  {
    login_response() = delete;
    static constexpr const char* endpoint() noexcept { return "/login"; }

    boost::optional<std::uint64_t> start_height;
    boost::optional<address_meta> lookahead;
    bool new_address;
  };
  void read_bytes(wire::json_reader&, login_response&);


  struct daemon_status
  {
    daemon_status() = delete;
    static constexpr const char* endpoint() noexcept { return "/daemon_status"; }
    std::uint64_t outgoing_connections_count;
    std::uint64_t incoming_connections_count;
    std::uint64_t height;
    std::uint64_t target_height;
  };
  void read_bytes(wire::json_reader&, daemon_status&);


  enum class feed_status : std::uint16_t
  {
    unspecified_error = 0,
    account_not_found,
    bad_address,
    bad_view_key,
    blockchain_reorg,
    daemon_unresponsive,
    parse_error,
    protocol_error,
    queue_error,
    schema_error
  };
  WIRE_AS_INTEGER(feed_status);

  struct feed
  {
    feed() = delete;
    static constexpr const char* endpoint() noexcept { return "/feed"; }
    static constexpr const char* protocol() noexcept { return "lws.feed.v0.msgpack"; }
  };
  void read_bytes(wire::json_reader&, const feed&);

  struct feed_tx
  { 
    struct legacy_id
    {
      legacy_id() = delete;
      std::uint64_t amount;
      std::uint64_t index;
    };

    struct output_id { legacy_id legacy; };

    struct receive
    {
      std::uint64_t amount;
      output_id id;
      address_meta recipient;
      std::uint16_t index;
      boost::optional<rct::key> rct;
      crypto::public_key public_key;
      crypto::public_key tx_pub_key;

      receive() noexcept
        : amount(0), id{}, recipient{}, index(0), rct(), public_key{}, tx_pub_key{}
      {}

      receive(std::uint64_t amount, const output_id& id, const address_meta& recipient, std::uint16_t index, const boost::optional<rct::key> rct, const crypto::public_key& public_key, const crypto::public_key& tx_pub_key) noexcept
        : amount(amount), id(id), recipient(recipient), index(index), rct(rct), public_key(public_key), tx_pub_key(tx_pub_key)
      {}
    };

    struct spend
    {
      output_id id;
      crypto::key_image key_image;

      spend() noexcept
        : id{}, key_image{}
      {}
    };

    std::vector<receive> receives;
    std::vector<spend> spends;
    std::uint64_t fee;
    std::uint64_t unlock_time;
    std::uint64_t height;
    std::chrono::system_clock::time_point timestamp;
    std::uint32_t mixin;
    std::variant<empty, crypto::hash8, crypto::hash> payment_id;
    crypto::hash hash;
    crypto::hash prefix_hash;
    bool coinbase;
    bool mempool;

    //! Hack because `boost/std::optional` sort left adjacent
    static constexpr std::uint64_t txpool() noexcept { return std::uint64_t(-1); }

    feed_tx()
      : receives(),
        spends(),
        unlock_time(0),
        height(),
        timestamp(),
        mixin(),
        payment_id(),
        hash{},
        prefix_hash{},
        coinbase(false),
        mempool(false)
    {}

    boost::optional<std::uint64_t> get_height() const noexcept
    { return boost::make_optional(height != txpool(), height); }
  };
  void read_bytes(wire::msgpack_reader&, feed_tx&);

  inline constexpr bool operator==(const feed_tx::output_id& lhs, const feed_tx::output_id& rhs) noexcept
  {
    return lhs.legacy.index == rhs.legacy.index && lhs.legacy.amount == rhs.legacy.amount;
  }
  inline constexpr bool operator!=(const feed_tx::output_id& lhs, const feed_tx::output_id& rhs) noexcept
  {
    return lhs.legacy.index != rhs.legacy.index || lhs.legacy.amount != rhs.legacy.amount;
  }
  inline constexpr bool operator<(const feed_tx::output_id& lhs, const feed_tx::output_id& rhs) noexcept
  {
    return lhs.legacy.amount == rhs.legacy.amount ?
      lhs.legacy.index < rhs.legacy.index : lhs.legacy.amount < rhs.legacy.amount;
  }

  struct feed_blocks
  {
    feed_blocks() = delete;
    static constexpr const char* prefix() noexcept { return "blocks:"; }

    std::vector<feed_tx> transactions;
    std::uint64_t scan_start;
    std::uint64_t scan_end;
    std::uint64_t blockchain_height;
    boost::optional<std::uint64_t> lookahead_fail;
    address_meta lookahead;
  };
  void read_bytes(wire::msgpack_reader&, feed_blocks&);

  struct feed_error
  {
    feed_error() = delete;
    static constexpr const char* prefix() noexcept { return "error:"; }

    std::string msg;
    feed_status code;
  };
  void read_bytes(wire::msgpack_reader&, feed_error&);

  struct feed_login
  {
    feed_login() = delete;
    static constexpr const char* prefix() noexcept { return "login:"; }
    login account;
  };
  void write_bytes(wire::msgpack_writer&, const feed_login&);

  //! One specific output is sent per-message
  struct feed_mempool
  {
    feed_mempool() = delete;
    static constexpr const char* prefix() noexcept { return "mempool:"; }

    std::uint64_t amount;
    std::uint64_t fee;
    std::uint64_t unlock_time;
    address_meta recipient;
    std::uint32_t mixin;
    std::variant<empty, crypto::hash8, crypto::hash> payment_id;
    boost::optional<rct::key> rct;
    crypto::hash hash;
    crypto::hash prefix_hash;
    crypto::public_key public_key;
    crypto::public_key tx_pub_key;
    std::uint16_t index;
  };
  void read_bytes(wire::msgpack_reader&, feed_mempool&);

  struct feed_tx_sync
  {
    feed_tx_sync() = delete;
    static constexpr const char* prefix() noexcept { return "tx_sync:"; }

    std::vector<feed_tx> transactions;
    std::uint64_t scanned_block_height;
    std::uint64_t start_height;
    std::uint64_t blockchain_height;
    boost::optional<std::uint64_t> lookahead_fail;
    address_meta lookahead;
  };
  void read_bytes(wire::msgpack_reader&, feed_tx_sync&);

  struct feed_warning
  {
    feed_warning() = delete;
    static constexpr const char* prefix() noexcept { return "warning:"; }

    std::string msg;
    std::uint64_t height;
    feed_status code;
  };
  void read_bytes(wire::msgpack_reader&, feed_warning&);


  enum class uint64_string : std::uint64_t {};
  void write_bytes(wire::json_writer&, uint64_string);
  void read_bytes(wire::json_reader&, uint64_string&); 
 
  struct transaction_spend
  {
    uint64_string amount;
    boost::optional<address_meta> sender;
    std::uint16_t out_index;
    crypto::key_image key_image;
    crypto::public_key tx_pub_key;

    transaction_spend() noexcept
      : amount(uint64_string(0)),
        sender(),
        out_index(0),
        key_image{},
        tx_pub_key{}
    {}

    transaction_spend(const feed_tx::spend& spend, const feed_tx::receive& receive) noexcept
      : amount(uint64_string(receive.amount)),
        sender(receive.recipient),
        out_index(receive.index),
        key_image(spend.key_image),
        tx_pub_key(receive.tx_pub_key)
    {}
  };
  void read_bytes(wire::json_reader&, transaction_spend&);

  struct transaction
  {
    std::vector<transaction_spend> spent_outputs;
    std::variant<empty, crypto::hash8, crypto::hash> payment_id;
    boost::optional<std::time_t> timestamp;
    boost::optional<uint64_string> fee;
    uint64_string total_received;
    std::uint64_t unlock_time;
    boost::optional<std::uint64_t> height;
    crypto::hash hash;
    bool coinbase;
    bool mempool;

    transaction()
      : spent_outputs(),
        payment_id(),
        timestamp(),
        fee(),
        total_received(uint64_string(0)),
        unlock_time(0),
        height(),
        hash{},
        coinbase(false),
        mempool(false)
    {}

    transaction(const feed_tx& src)
      : spent_outputs(),
        payment_id(src.payment_id),
        timestamp(std::chrono::system_clock::to_time_t(src.timestamp)),
        fee(uint64_string(src.fee)),
        total_received(uint64_string(0)),
        unlock_time(src.unlock_time),
        height(src.get_height()),
        hash(src.hash),
        coinbase(src.coinbase),
        mempool(src.mempool)
    {
      std::uint64_t total = 0;
      for (const auto& received : src.receives)
        total += received.amount;
      total_received = uint64_string(total);
    }
  };
  void read_bytes(wire::json_reader&, transaction&);
  
  struct get_address_txs
  {
    get_address_txs() = delete;
    static constexpr const char* endpoint() noexcept { return "/get_address_txs"; }

    std::vector<transaction> transactions;
    boost::optional<std::uint64_t> lookahead_fail;
    std::uint64_t scanned_block_height;
    std::uint64_t start_height;
    std::uint64_t blockchain_height;
    address_meta lookahead;
  };
  void read_bytes(wire::json_reader&, get_address_txs&);


  struct get_version
  {
    get_version() = delete;
    static constexpr const char* endpoint() noexcept { return "/get_version"; }

    std::uint64_t max_subaddresses;
  };
  void read_bytes(wire::json_reader&, get_version&);


  struct random_output
  {
    random_output()
      : global_index(uint64_string(0)), public_key{}, rct{}
    {}

    uint64_string global_index;
    rct::key public_key;
    rct::key rct;
  };
  void read_bytes(wire::json_reader&, random_output&);

  struct random_outputs
  {
    random_outputs()
      : outputs(), amount(uint64_string(0))
    {}

    std::vector<random_output> outputs;
    uint64_string amount;
  };
  void read_bytes(wire::json_reader&, random_outputs&);

  struct get_random_outs_request
  {
    get_random_outs_request() = delete;

    std::vector<uint64_string> amounts;
    std::uint32_t count; // mixin
  };
  void write_bytes(wire::json_writer&, const get_random_outs_request&);

  struct get_random_outs_response
  {
    get_random_outs_response() = delete;
    static constexpr const char* endpoint() noexcept { return "/get_random_outs"; }

    std::vector<random_outputs> amount_outs;
  };
  void read_bytes(wire::json_reader&, get_random_outs_response&);


  struct subaddrs
  {
    subaddrs() noexcept
      : value()
    {}

    explicit subaddrs(const std::uint32_t last) noexcept
      : value()
    {
      value.insert({0, last});
    }

    //! \return true if `this` represents a canonical range of values.
    bool is_valid() const noexcept;

    // Merge `{0, index}` to the set of subaddresses.
    void merge(std::uint32_t index);

    boost::container::flat_set<std::array<std::uint32_t, 2>, std::less<>> value;
  };
  WIRE_JSON_DECLARE_OBJECT(subaddrs);
  void read_bytes(wire::json_reader&, subaddrs&);

  struct get_subaddrs
  {
    using mapped_type = std::pair<std::uint32_t, subaddrs>;
    get_subaddrs() = delete;
    static constexpr const char* endpoint() noexcept { return "/get_subaddrs"; }

    boost::container::flat_map<std::uint32_t, subaddrs> all_subaddrs;
  };
  WIRE_JSON_DECLARE_OBJECT(get_subaddrs::mapped_type);
  void read_bytes(wire::json_reader&, get_subaddrs&);


  struct ringct
  {
    enum class format : std::uint8_t
    {
      none = 0, //!< Not ringct
      encrypted,
      recompute,
      unencrypted
    };

    ringct() noexcept
      : mask{}, type(format::none)
    {}

    ringct(const rct::key& mask, const format type) noexcept
      : mask(mask), type(type)
    {}

    ringct(const boost::optional<rct::key>& src) noexcept
      : mask(src.value_or(rct::key{})),
        type(bool(src) ? format::unencrypted : format::none)
    {}

    rct::key mask;
    format type;
  };

  struct output
  {
    uint64_string amount;
    uint64_string global_index;
    boost::optional<address_meta> recipient;
    std::uint16_t index;
    ringct rct;
    crypto::hash tx_hash;	
    crypto::hash tx_prefix_hash;
    crypto::public_key public_key;
    crypto::public_key tx_pub_key;

    output() noexcept
      : amount(uint64_string(0)),
        global_index(uint64_string(0)),
        recipient(),
        index(0),
        rct{},
        tx_hash{},
        tx_prefix_hash{},
        public_key{},
        tx_pub_key{}
    {}

    output(const feed_mempool& src) noexcept
      : amount(uint64_string(src.amount)),
        global_index(uint64_string(std::numeric_limits<std::uint64_t>::max())),
        recipient(src.recipient),
        index(src.index),
        rct(src.rct),
        tx_hash(src.hash),
        tx_prefix_hash(src.prefix_hash),
        public_key(src.public_key),
        tx_pub_key(src.tx_pub_key)
    {}

    output(const feed_tx::receive& src, const feed_tx& tx) noexcept
      : amount(uint64_string(src.amount)),
        global_index(uint64_string(src.id.legacy.index)),
        recipient(src.recipient),
        index(src.index),
        rct(src.rct),
        tx_hash(tx.hash),
        tx_prefix_hash(tx.prefix_hash),
        public_key(src.public_key),
        tx_pub_key(src.tx_pub_key)
    {}
  };
  void read_bytes(wire::json_reader&, output&);

  struct get_unspent_outs_request
  {
    get_unspent_outs_request() = delete;
    login creds;
    uint64_string amount;
    std::uint32_t mixin;
    bool use_dust;
  };
  void write_bytes(wire::json_writer&, const get_unspent_outs_request&);

  struct get_unspent_outs_response
  {
    get_unspent_outs_response() = delete;
    static constexpr const char* endpoint() noexcept { return "/get_unspent_outs"; }

    std::vector<output> outputs;
    std::vector<std::uint64_t> fees;
    std::uint64_t per_byte_fee;
    std::uint64_t fee_mask;
  };
  void read_bytes(wire::json_reader&, get_unspent_outs_response&);


  struct import_request
  {
    import_request() = delete;
    login creds;
    std::uint64_t from_height;
    address_meta lookahead;
  };
  void write_bytes(wire::json_writer&, const import_request&);

  struct import_response
  {
    import_response() = delete;
    import_response(import_response&&) = default;
    import_response(const import_response&) = delete;
    import_response& operator=(import_response&&) = default;
    import_response& operator=(const import_response&) = delete;
    static constexpr const char* endpoint() noexcept { return "/import_wallet_request"; }

    boost::optional<std::string> payment_address;
    boost::optional<epee::byte_slice> payment_id;
    boost::optional<uint64_string> import_fee;
    boost::optional<address_meta> lookahead;
    std::string status;
    bool new_request;
    bool request_fulfilled;
  };
  void read_bytes(wire::json_reader&, import_response&);

  
  struct provision_subaddrs_request
  {
    provision_subaddrs_request() = delete;
    login creds;
    std::uint32_t maj_i;
    std::uint32_t min_i;
    std::uint32_t n_maj;
    std::uint32_t n_min;
    bool get_all;
  };
  void write_bytes(wire::json_writer&, const provision_subaddrs_request&);

  struct provision_subaddrs_response
  {
    provision_subaddrs_response() = delete;
    static constexpr const char* endpoint() noexcept { return "/provision_subaddrs"; }

    boost::container::flat_map<std::uint32_t, subaddrs> new_subaddrs;
    boost::container::flat_map<std::uint32_t, subaddrs> all_subaddrs;
  };
  void read_bytes(wire::json_reader&, provision_subaddrs_response&);


  struct submit_raw_tx_request
  {
    submit_raw_tx_request() = delete;
    epee::byte_slice tx;
  };
  void write_bytes(wire::json_writer&, const submit_raw_tx_request&);

  struct submit_raw_tx_response
  {
    submit_raw_tx_response() = delete;
    static constexpr const char* endpoint() noexcept { return "/submit_raw_tx"; }

    std::string status;
  };
  void read_bytes(wire::json_reader&, submit_raw_tx_response&);


  struct upsert_subaddrs_request
  {
    upsert_subaddrs_request() = delete;
    login creds;
    boost::container::flat_map<std::uint32_t, subaddrs> subaddrs_;
    bool get_all;
  };
  void write_bytes(wire::json_writer&, const upsert_subaddrs_request&);

  struct upsert_subaddrs_response
  {
    upsert_subaddrs_response() = delete;
    static constexpr const char* endpoint() noexcept { return "/upsert_subaddrs"; }
  };
  void read_bytes(wire::json_reader&, upsert_subaddrs_response&);
     
}}} // lwsf // internal // rpc

WIRE_DECLARE_BLOB(lwsf::internal::rpc::ringct);

