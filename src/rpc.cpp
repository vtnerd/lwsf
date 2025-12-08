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

#include "rpc.h"

#include <boost/spirit/include/qi_char.hpp>
#include <boost/spirit/include/qi_uint.hpp>
#include <boost/spirit/include/qi_parse_attr.hpp>
#include <boost/spirit/include/qi_sequence.hpp>
#include <ctime>
#include "hex.h"             // monero/contrib/epee/include
#include "lwsf_config.h"
#include "net/http_client.h" // monero/contrib/epee/include
#include "ringct/rctOps.h"   // monero/contrib/epee/include
#include "wire.h"
#include "wire/adapted/array.h"
#include "wire/adapted/crypto.h"
#include "wire/field.h"
#include "wire/json.h"
#include "wire/traits.h"
#include "wire/wrapper/array.h"
#include "wire/wrapper/trusted_array.h"
#include "wire/wrappers_impl.h"

namespace lwsf { namespace internal { namespace rpc
{
  namespace
  {
    //! \return Error message string.
    const char* get_string(error value) noexcept
    {
      switch (value)
      {
      default:
        break;

      case error::none:
        return "No rpc errors";
      case error::no_response:
        return "No response from HTTP server";
      case error::invalid_code:
        return "Invalid status code from HTTP server";
      }
      return nullptr;
    }
  }

  //! \return Category for `error`.
  const std::error_category& error_category() noexcept
  {
    struct category final : std::error_category
    {
      virtual const char* name() const noexcept override final
      {
        return "lwsf::internal::rpc::error_category()";
      }

      virtual std::string message(int value) const override final
      {
        char const * const msg = get_string(error(value));
        if (msg)
          return msg;
        return "HTTP error code " + std::to_string(value);
      }
    };
    static const category instance{};
    return instance;
  }

  expect<std::string> invoke_payload(http_client& client, const boost::string_ref endpoint, const epee::byte_slice payload)
  {
    static const epee::net_utils::http::fields_list headers{
      {"Content-Type", "application/json; charset=utf-8"}
    };

    if (!client.is_connected())
    {
      if (client.connect(config::connect_timeout))
        return {error::no_response};
    }

    const epee::net_utils::http::http_response_info* response = nullptr;
    if (!client.invoke(endpoint, "POST", {reinterpret_cast<const char*>(payload.data()), payload.size()}, config::rpc_timeout, std::addressof(response), headers))
      return {error::no_response};
    if (!response)
      return {error::no_response};
    if(response->m_response_code == 200 || response->m_response_code == 201)
      return response->m_body;

    if (response->m_response_code <= 0 || std::numeric_limits<int>::max() < response->m_response_code)
      return {error::invalid_code};
    return {error(int(response->m_response_code))};
  }

  void write_bytes(wire::writer& dest, const empty&)
  { wire::object(dest); }
  void read_bytes(wire::reader& source, empty&)
  { wire::object(source); }

  void write_bytes(wire::json_writer& dest, const login& self)
  {
    wire::object(dest, WIRE_FIELD(address), WIRE_FIELD(view_key));
  }
 
  void write_bytes(wire::json_writer& dest, const login_request& self)
  {
    wire::object(dest,
      WIRE_FIELD(address),
      WIRE_FIELD(view_key),
      WIRE_FIELD(create_account),
      WIRE_FIELD(generated_locally)
    );
  }

  void read_bytes(wire::json_reader& source, login_response& self)
  {
    wire::object(source, WIRE_OPTIONAL_FIELD(start_height), WIRE_FIELD(new_address));
  }

  void read_bytes(wire::json_reader& source, daemon_status& self)
  {
    wire::object(source, 
      WIRE_FIELD(outgoing_connections_count),
      WIRE_FIELD(incoming_connections_count),
      WIRE_FIELD(height),
      WIRE_FIELD(target_height)
    );

  }

  void write_bytes(wire::json_writer& dest, const uint64_string source)
  {
    const auto as_string = dest.to_string(std::uintmax_t(source));
    dest.string({as_string.data()});
  }

  void read_bytes(wire::json_reader& source, uint64_string& dest)
  {
    dest = uint64_string(wire::integer::cast_unsigned<std::uint64_t>(source.safe_unsigned_integer()));
  } 

  namespace
  {
    template<typename F, typename T>
    void map_address_meta(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(maj_i), WIRE_FIELD(min_i));
    }
  }

  WIRE_DEFINE_OBJECT(address_meta, map_address_meta);

  void read_bytes(wire::json_reader& source, transaction_spend& self)
  {
    wire::object(source,
      WIRE_FIELD(amount),
      WIRE_OPTIONAL_FIELD(sender),
      WIRE_FIELD(out_index),
      WIRE_FIELD(key_image),
      WIRE_FIELD(tx_pub_key)
    );
  }

  void read_bytes(wire::json_reader& source, transaction& self)
  {
    using min_spent = wire::min_element_sizeof<crypto::key_image>;

    boost::optional<std::string> timestamp;
    boost::optional<epee::byte_slice> payment_id;
    wire::object(source,
      WIRE_FIELD_ARRAY(spent_outputs, min_spent),
      wire::optional_field("payment_id", std::ref(payment_id)),
      wire::optional_field("timestamp", std::ref(timestamp)),
      WIRE_OPTIONAL_FIELD(fee),
      WIRE_FIELD(total_received),
      WIRE_FIELD(unlock_time),
      WIRE_OPTIONAL_FIELD(height),
      WIRE_FIELD(hash),
      WIRE_FIELD(coinbase),
      WIRE_FIELD(mempool)
    );

    if (payment_id && !payment_id->empty())
    {
      if (payment_id->size() == sizeof(crypto::hash8))
      {
        self.payment_id = crypto::hash8{};
        std::memcpy(std::addressof(std::get<crypto::hash8>(self.payment_id)), payment_id->data(), sizeof(crypto::hash8));
      }
      else if (payment_id->size() == sizeof(crypto::hash))
      {
        self.payment_id = crypto::hash{};
        std::memcpy(std::addressof(std::get<crypto::hash>(self.payment_id)), payment_id->data(), sizeof(crypto::hash));
      }
      else
        WIRE_DLOG_THROW(wire::error::schema::fixed_binary, "Invalid payment_id size");
    }
    else
      self.payment_id = empty{};

    self.timestamp.reset();

    if (timestamp)
    {
      //  %Y-%m-%dT%H:%M:%SZ
      namespace qi = boost::spirit::qi;
      std::tm fields{};
      if (!qi::parse(timestamp->begin(), timestamp->end(), qi::ushort_ >> '-' >> qi::ushort_ >> '-' >> qi::ushort_ >> 'T' >> qi::ushort_ >> ':' >> qi::ushort_ >> ':' >> qi::ushort_ >> 'Z', fields.tm_year, fields.tm_mon, fields.tm_mday, fields.tm_hour, fields.tm_min, fields.tm_sec))
        WIRE_DLOG_THROW(wire::error::schema::string, "Timestamp string invalid format");

      fields.tm_year -= 1900;
      --fields.tm_mon;
      fields.tm_isdst = 0;
      self.timestamp = timegm(std::addressof(fields));
    }
  }

  void read_bytes(wire::json_reader& source, get_address_txs& self)
  {
    using max_transactions = wire::max_element_count<config::max_txes_in_rpc>; 
    wire::object(source,
      WIRE_FIELD_ARRAY(transactions, max_transactions),
      WIRE_FIELD(scanned_block_height),
      WIRE_FIELD(start_height),
      WIRE_FIELD(blockchain_height)
    );
  }


  void read_bytes(wire::json_reader& source, random_output& self)
  {
    epee::byte_slice rct;
    wire::object(source,
      WIRE_FIELD(global_index),
      WIRE_FIELD(public_key),
      wire::field("rct", std::ref(rct))
    );

    if (rct.size() < sizeof(self.rct))
      WIRE_DLOG_THROW_(wire::error::schema::fixed_binary);
    std::memcpy(std::addressof(self.rct), rct.data(), sizeof(self.rct));
  }

  void read_bytes(wire::json_reader& source, random_outputs& self)
  {
    using max_ring = wire::max_element_count<config::max_ring_size_in_rpc>;
    wire::object(source, WIRE_FIELD_ARRAY(outputs, max_ring), WIRE_FIELD(amount));
  }

  void write_bytes(wire::json_writer& dest, const get_random_outs_request& self)
  {
    using unused = wire::max_element_count<0>;
    wire::object(dest, WIRE_FIELD_ARRAY(amounts, unused), WIRE_FIELD(count));
  }

  void read_bytes(wire::json_reader& source, get_random_outs_response& self)
  {
    using max_inputs = wire::max_element_count<config::max_inputs_in_rpc>;
    wire::object(source, WIRE_FIELD_ARRAY(amount_outs, max_inputs));
  }


  namespace
  {
    //! A wrapper that simulates an array by only using the first element
    template<typename T>
    class array_head_
    {
      T head_;
      wire::unwrap_reference_t<T> tail_;
      std::size_t count_;

    public:
        using value_type = wire::unwrap_reference_t<T>;
        using iterator = std::add_pointer_t<value_type>;
        using const_iterator = std::add_pointer_t<std::add_const_t<value_type>>;
        using reference = std::add_lvalue_reference_t<value_type>;
        using const_reference = std::add_lvalue_reference_t<std::add_const_t<value_type>>;

        constexpr array_head_(T head)
          : head_(std::move(head)), tail_{}, count_(1)
        {}

        void clear() noexcept { count_ = 0; }
        bool empty() const noexcept { return !size(); }
        std::size_t size() const noexcept { return count_; }
        const_iterator begin() const noexcept { return std::addressof(front()); }
        const_iterator end() const
        {
          if (1 < size())
            throw std::logic_error{"Unexpected call to subaddr_adaptr::end"};
          return empty() ? begin() : begin() + 1;
        }

        reference front() noexcept { return head_; }
        const_reference front() const noexcept { return head_; }
        reference back() noexcept { return 1 < size() ? tail_ : front(); }
        void push_back() noexcept { ++count_; }
        reference emplace_back() noexcept { push_back(); return back(); }
    };

    template<typename T>
    constexpr array_head_<T> array_head(T val)
    { return {std::move(val)}; }

    template<typename F, typename T>
    void map_subaddrs(F& format, T& self)
    {
      auto head = array_head(std::ref(self.head));
      wire::object(format,
        WIRE_FIELD(key),
        wire::field("value", wire::trusted_array(std::ref(head)))
      );
      if (head.empty())
        WIRE_DLOG_THROW(wire::error::schema::array, "unexpected empty array");
    }
  }
 
  WIRE_JSON_DEFINE_OBJECT(subaddrs, map_subaddrs); 
  void read_bytes(wire::json_reader& source, get_subaddrs& self)
  {
    wire::object(source, WIRE_FIELD_ARRAY(all_subaddrs, max_subaddrs));
  }


  namespace
  {
    // This field is a mess between implementations, this cleans it up a bit
    struct convert_rct
    {
      ringct operator()(const std::nullptr_t&) const noexcept
      {
        return ringct{{}, ringct::format::none};
      }

      ringct operator()(const std::string& source) const
      {
        struct ringct_triplet
        {
          ringct_triplet() = delete;
          rct::key commitment;
          rct::key mask;
          rct::key amount;
        };
        static_assert(sizeof(ringct_triplet) == 96);

        if (source.empty())
          return ringct{{}, ringct::format::none};

        rct::key out{};
        if (source == "coinbase") // non-standard, openmonero
          return ringct{rct::identity(), ringct::format::unencrypted}; 
        else if (source.size() == sizeof(ringct_triplet) * 2)
        {
          ringct_triplet rct{};
          if (!epee::from_hex::to_buffer(epee::as_mut_byte_span(rct), source))
            WIRE_DLOG_THROW(wire::error::schema::binary, "Invalid hex for ringct");
          if (rct.amount == rct::key{} && rct.mask == rct::identity())
            return ringct{rct::identity(), ringct::format::unencrypted};
          return ringct{rct.mask, ringct::format::encrypted}; 
        }

        return ringct{{}, ringct::format::recompute};
      }

      template<typename T>
      ringct operator()(const T&) const
      {
        WIRE_DLOG_THROW(wire::error::schema::string, "Expected string or null");
      }
    };
  }

  void read_bytes(wire::json_reader& source, output& self)
  {
    wire::basic_value raw_rct{};
    wire::object(source,
      WIRE_FIELD(amount),
      WIRE_FIELD(index),
      WIRE_FIELD(global_index),
      WIRE_OPTIONAL_FIELD(recipient),
      wire::optional_field("rct", std::ref(raw_rct)),
      WIRE_FIELD(tx_hash),
      WIRE_FIELD(tx_prefix_hash),
      WIRE_FIELD(public_key),
      WIRE_FIELD(tx_pub_key)
    );
    self.rct = std::visit(convert_rct{}, raw_rct.value);
  }

  void write_bytes(wire::json_writer& dest, const get_unspent_outs_request& self)
  {
    wire::object(dest,
      wire::field("address", std::cref(self.creds.address)),
      wire::field("view_key", std::cref(self.creds.view_key)),
      WIRE_FIELD_COPY(amount),
      WIRE_FIELD_COPY(mixin),
      WIRE_FIELD_COPY(use_dust)
    ); 
  }

  void read_bytes(wire::json_reader& source, get_unspent_outs_response& self)
  {
    using min_output_size = wire::min_element_sizeof<
      ringct, crypto::hash, crypto::hash, crypto::public_key, crypto::public_key
    >;
    using max_fees = wire::max_element_count<8>;
    wire::object(source,
      WIRE_FIELD_ARRAY(outputs, min_output_size),
      WIRE_FIELD_ARRAY(fees, max_fees),
      WIRE_FIELD(per_byte_fee),
      WIRE_FIELD(fee_mask)
    );
  }


  void write_bytes(wire::json_writer& source, const import_request& self)
  {
    wire::object(source,
      wire::field("address", std::cref(self.creds.address)),
      wire::field("view_key", std::cref(self.creds.view_key)),
      WIRE_FIELD(from_height)
    );
  }

  void read_bytes(wire::json_reader& source, import_response& self)
  {
    wire::object(source,
      WIRE_OPTIONAL_FIELD(payment_address),
      WIRE_OPTIONAL_FIELD(payment_id),
      WIRE_OPTIONAL_FIELD(import_fee),
      WIRE_FIELD(status),
      WIRE_FIELD(new_request),
      WIRE_FIELD(request_fulfilled)
    );
  }


  void write_bytes(wire::json_writer& dest, const provision_subaddrs_request& self)
  {
    wire::object(dest,
      wire::field("address", std::cref(self.creds.address)),
      wire::field("view_key", std::cref(self.creds.view_key)),
      WIRE_FIELD_COPY(maj_i),
      WIRE_FIELD_COPY(min_i),
      WIRE_FIELD_COPY(n_maj),
      WIRE_FIELD_COPY(n_min),
      WIRE_FIELD_COPY(get_all)
    );
  }

  void read_bytes(wire::json_reader& source, provision_subaddrs_response& self)
  {
    wire::object(source,
      WIRE_FIELD_ARRAY(new_subaddrs, max_subaddrs), 
      WIRE_FIELD_ARRAY(all_subaddrs, max_subaddrs)
    );
  }


  void write_bytes(wire::json_writer& dest, const submit_raw_tx_request& self)
  {
    wire::object(dest, WIRE_FIELD(tx));
  }

  void read_bytes(wire::json_reader& source, submit_raw_tx_response& self)
  {
    wire::object(source, WIRE_FIELD(status));
  }


  void write_bytes(wire::json_writer& dest, const upsert_subaddrs_request& self)
  {
    wire::object(dest,
      wire::field("address", std::cref(self.creds.address)),
      wire::field("view_key", std::ref(self.creds.view_key)),
      wire::field("subaddrs", wire::array(std::ref(self.subaddrs_))), // always write field (not optional)
      WIRE_FIELD_COPY(get_all)
    );
  }

  void read_bytes(wire::json_reader& source, upsert_subaddrs_response& self)
  {
    wire::object(source,
      WIRE_FIELD_ARRAY(new_subaddrs, max_subaddrs),
      WIRE_FIELD_ARRAY(all_subaddrs, max_subaddrs)
    );
  }
}}} // lwsf // internal // rpc

