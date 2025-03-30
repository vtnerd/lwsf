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

#include <boost/variant.hpp>
#include <ctime>
#include <optional>
#include <system_error>
#include "byte_slice.h"  // monero/contrib/epee/include
#include "byte_stream.h" // moneor/contrib/epee/include
#include "common/expect.h"   // monero/src
#include "crypto/crypto.h"   // monero/src
#include "ringct/rctTypes.h" // monero/src
#include "wire/basic_value.h"
#include "wire/fwd.h"
#include "wire/json.h"

namespace epee { namespace net_utils
{
  class blocked_mode_client;
  namespace http { template<typename> class http_simple_client_template; }
}}

namespace lwsf { namespace internal { namespace rpc
{
  using http_client = epee::net_utils::http::http_simple_client_template<
    epee::net_utils::blocked_mode_client
  >;

  enum class error : int
  {
    none = 0, invoke_failure, not_connected, wrong_response_code
  };

  const char* get_string(error value) noexcept;
  const std::error_category& error_category() noexcept;
  inline std::error_code make_error_code(const error value) noexcept
  {
    return std::error_code{int(value), error_category()};
  }

  //! Send `payload` to `client` at uri `endpoint`, and \return payload response
  expect<std::string> invoke_payload(http_client& client, boost::string_ref endpoint, epee::byte_slice payload);

  template<typename F, typename G>
  expect<F> invoke(http_client& client, const G& in)
  {
    epee::byte_stream sink{};
    std::error_code error = wire::json::to_bytes(sink, in);
    if (error)
      return error;

    expect<std::string> result = invoke_payload(client, F::endpoint(), epee::byte_slice{std::move(sink)});
    if (!result)
      return result.error();
    
    F out{};
    error = wire::json::from_bytes(std::move(*result), out);
    if (error)
      return error;
    return out;
  }

  struct empty {};
  WIRE_DECLARE_OBJECT(empty);
 
  struct login
  {
    login() = delete;

    std::string address;
    crypto::secret_key view_key;
  };
  void write_bytes(wire::json_writer&, const login&); 

 
  struct login_request
  {
    login_request() = delete;

    std::string address;
    crypto::secret_key view_key;
    bool create_account;
    bool generated_locally;
  };
  void write_bytes(wire::json_writer&, const login_request&);

  struct login_response
  {
    login_response() = delete;
    static constexpr const char* endpoint() noexcept { return "/login"; }

    std::optional<std::uint64_t> start_height;
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


  enum class uint64_string : std::uint64_t {};
  void read_bytes(wire::json_reader&, uint64_string&); 

  struct address_meta
  {
    std::uint32_t maj_i;
    std::uint32_t min_i;

    address_meta() noexcept
      : maj_i(0), min_i(0)
    {}

    address_meta(const std::uint32_t maj, std::uint32_t min) noexcept
      : maj_i(maj), min_i(min)
    {}
  };
  WIRE_DECLARE_OBJECT(address_meta);

  struct transaction_spend
  {
    uint64_string amount;
    std::optional<address_meta> sender;
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
  };
  void read_bytes(wire::json_reader&, transaction_spend&);

  struct transaction
  {
    std::vector<transaction_spend> spent_outputs;
    std::variant<empty, crypto::hash8, crypto::hash> payment_id;
    std::optional<std::time_t> timestamp;
    std::optional<uint64_string> fee;
    uint64_string total_received;
    std::uint64_t unlock_time;
    std::optional<std::uint64_t> height;
    crypto::hash tx_hash;
    bool is_coinbase;
    bool mempool;

    transaction()
      : spent_outputs(),
        payment_id(),
        timestamp(),
        fee(),
        total_received(uint64_string(0)),
        unlock_time(0),
        height(),
        tx_hash{},
        is_coinbase(false),
        mempool(false)
    {}
  };
  void read_bytes(wire::json_reader&, transaction&);
  
  struct get_address_txs
  {
    get_address_txs() = delete;
    static constexpr const char* endpoint() noexcept { return "/get_address_txs"; }

    std::vector<transaction> transactions;
    std::uint64_t scanned_block_height;
    std::uint64_t start_height;
    std::uint64_t blockchain_height;
  };
  void read_bytes(wire::json_reader&, get_address_txs&);


  struct subaddrs
  {
    subaddrs()
      : key(0), value()
    {}

    std::uint32_t key;
    std::vector<std::array<std::uint32_t, 2>> value; 
  };
  void read_bytes(wire::json_reader&, subaddrs&);

  struct get_subaddrs
  {
    get_subaddrs() = delete;
    static constexpr const char* endpoint() noexcept { return "/get_subaddrs"; }

    std::vector<subaddrs> all_subaddrs;
  };
  void read_bytes(wire::json_reader&, get_subaddrs&);


  struct ringct
  {
    ringct() = delete;

    enum class format : std::uint8_t
    {
      none = 0, //!< Not ringct
      encrypted,
      recompute,
      unencrypted
    };

    rct::key mask;
    format type;
  };

  struct output
  {
    uint64_string amount;
    uint64_string global_index;
    std::optional<address_meta> recipient;
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
  };
  void read_bytes(wire::json_reader&, output&);

  struct get_unspent_outs
  {
    get_unspent_outs() = delete;
    static constexpr const char* endpoint() noexcept { return "/get_unspent_outs"; }

    std::vector<output> outputs;
    std::uint64_t per_byte_fee;
    std::uint64_t fee_mask;
  };
  void read_bytes(wire::json_reader&, get_unspent_outs&);


  struct import_response
  {
    import_response() = delete;
    std::optional<uint64_string> import_fee;
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

    std::vector<subaddrs> new_subaddrs;
    std::vector<subaddrs> all_subaddrs;
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
     
}}} // lwsf // internal // rpc

WIRE_DECLARE_BLOB_NS(lwsf::internal::rpc::ringct);

namespace std
{
  template<>
  struct is_error_code_enum<lwsf::internal::rpc::error>
    : true_type
  {};
}
