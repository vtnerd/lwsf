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
#include "wire/wrappers_impl.h"

namespace lwsf { namespace internal { namespace rpc
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
    case error::invoke_failure:
      return "HTTP invoke failed";
    case error::not_connected:
      return "No connection to HTTP server";
    case error::wrong_response_code:
      return "Expected HTTP 200 OK";
    }
    return "Unknown rpc error";
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
        return get_string(error(value));
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

    const epee::net_utils::http::http_response_info* response = nullptr;
    if (!client.invoke(endpoint, "POST", {reinterpret_cast<const char*>(payload.data()), payload.size()}, config::rpc_timeout, std::addressof(response), headers))
      return {error::invoke_failure};
    if (!response)
      return {error::invoke_failure};
    if(response->m_response_code != 200 && response->m_response_code != 201)
      return {error::wrong_response_code};

    return response->m_body;
  }

  void write_bytes(wire::writer& dest, const empty&)
  { dest.boolean(true); }
  void read_bytes(wire::reader& source, const empty&)
  { source.boolean(); }

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
    wire::object(source, WIRE_OPTIONAL_FIELD(start_height));
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

    std::optional<std::string> timestamp;
    std::optional<epee::byte_slice> payment_id;
    wire::object(source,
      WIRE_FIELD_ARRAY(spent_outputs, min_spent),
      wire::optional_field("payment_id", std::ref(payment_id)),
      wire::optional_field("timestamp", std::ref(timestamp)),
      WIRE_OPTIONAL_FIELD(fee),
      WIRE_FIELD(total_received),
      WIRE_FIELD(unlock_time),
      WIRE_OPTIONAL_FIELD(height),
      WIRE_FIELD(tx_hash),
      WIRE_FIELD(is_coinbase),
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
      if (!qi::parse(timestamp->begin(), timestamp->end(), qi::ushort_ >> '-' >> qi::ushort_ >> '-' >> qi::ushort_ >> 'T' >> qi::ushort_ >> ':' >> qi::ushort_ >> qi::ushort_ >> 'Z', fields.tm_year, fields.tm_mon, fields.tm_mday, fields.tm_hour, fields.tm_min, fields.tm_sec))
        WIRE_DLOG_THROW(wire::error::schema::string, "Timestamp string invalid format");
      if ((self.timestamp = std::mktime(std::addressof(fields))) == -1)
        WIRE_DLOG_THROW(wire::error::schema::string, "Invalid timestamp value");
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

  void read_bytes(wire::json_reader& source, get_subaddrs& self)
  {
    using limits = wire::max_element_count<16384>;
    wire::object(source, WIRE_FIELD_ARRAY(all_subaddrs, limits));
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

  void read_bytes(wire::json_reader& source, get_unspent_outs& self)
  {
    using min_output_size = wire::min_element_sizeof<
      ringct, crypto::hash, crypto::hash, crypto::public_key, crypto::public_key
    >;
    wire::object(source,
      WIRE_FIELD_ARRAY(outputs, min_output_size),
      WIRE_FIELD(per_byte_fee),
      WIRE_FIELD(fee_mask)
    );
  }


  void read_bytes(wire::json_reader& source, import_response& self)
  {
    wire::object(source,
      WIRE_OPTIONAL_FIELD(import_fee),
      WIRE_FIELD(request_fulfilled)
    );
  }


  void read_bytes(wire::json_reader& source, subaddrs& self)
  {
    using limits = wire::min_element_size<2>;
    wire::object(source, WIRE_FIELD(key), WIRE_FIELD_ARRAY(value, limits));
  }

  void write_bytes(wire::json_writer& dest, const provision_subaddrs_request& self)
  {
    wire::object(dest,
      wire::field("address", std::cref(self.creds.address)),
      wire::field("view_key", std::cref(self.creds.view_key)),
      WIRE_FIELD(maj_i),
      WIRE_FIELD(min_i),
      WIRE_FIELD(n_maj),
      WIRE_FIELD(n_min),
      WIRE_FIELD(get_all)
    );
  }

  void read_bytes(wire::json_reader& source, provision_subaddrs_response& self)
  {
    using limits = wire::max_element_count<16384>;
    wire::object(source,
      WIRE_FIELD_ARRAY(new_subaddrs, limits), 
      WIRE_FIELD_ARRAY(all_subaddrs, limits)
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
}}} // lwsf // internal // rpc

