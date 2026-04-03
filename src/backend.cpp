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

#include "net/http_client.h"   // monero/contrib/epee/include
#include "backend.h"

#include <boost/asio/coroutine.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/thread/lock_guard.hpp>
#include "carrot_core/device_ram_borrowed.h"          // monero/src
#include "carrot_core/enote_utils.h"                  // monero/src
#include "carrot_core/scan.h"                         // monero/src
#include "carrot_impl/address_device_ram_borrowed.h"  // monero/src
#include "carrot_impl/format_utils.h"                 // monero/src
#include "carrot_impl/key_image_device_composed.h"    // monero/src
#include "carrot_impl/tx_builder_inputs.h"            // monero/src
#include "carrot_impl/tx_builder_outputs.h"           // monero/src
#include "carrot_impl/tx_proposal_utils.h"            // monero/src
#include "common/apply_permutation.h"                 // monero/src
#include "crypto/crypto.h"     // monero/src
#include "crypto/crypto-ops.h" // monero/src
#include "cryptonote_basic/cryptonote_basic_impl.h"   // monero/src
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "error.h"
#include "fcmp_pp/curve_trees.h"                      // monero/src
#include "fcmp_pp/tree_cache.h"                       // monero/src
#include "hex.h"               // monero/src
#include "lwsf_config.h"
#include "numeric.h"
#include "ringct/rctOps.h"
#include "wallet/tx_builder.h" // monero/src
#include "wire.h"
#include "wire/adapted/carrot.h"
#include "wire/adapted/crypto.h"
#include "wire/adapted/pair.h"
#include "wire/msgpack.h"
#include "wire/wrapper/defaulted.h"
#include "wire/wrapper/trusted_array.h"
#include "wire/wrapper/variant.h"

namespace Monero
{
  WIRE_AS_INTEGER(TransactionInfo::Direction);
  WIRE_AS_INTEGER(Monero::NetworkType);
}

namespace lwsf { namespace config
{
  namespace
  {
    template<typename F, typename T>
    void map_lookahead(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(major), WIRE_FIELD(minor));
    }
  } // anonymous
  WIRE_DEFINE_OBJECT(lookahead, map_lookahead);

  constexpr bool operator==(const lookahead& lhs, const lookahead& rhs) noexcept
  { return lhs.major == rhs.major && lhs.minor == rhs.minor; }

  constexpr bool operator!=(const lookahead& lhs, const lookahead& rhs) noexcept
  { return lhs.major != rhs.major || lhs.minor != rhs.minor; }

}} // lwsf // config

namespace lwsf { namespace internal { namespace backend
{ 
  namespace
  {
    constexpr const error default_subaddr_state = error::subaddr_disabled;
    constexpr const auto rpc_unapproved = http::error(403);
    constexpr const auto rpc_max_subaddresses = http::error(409);
    constexpr const auto rpc_internal_error = http::error(500);
    constexpr const auto rpc_not_implemented = http::error(501);

    template<typename T, typename U>
    std::uint32_t add_uint32_clamp(const T index, const U lookahead)
    {
      static_assert(std::is_unsigned<T>());
      static_assert(std::is_same<U, std::uint32_t>());
      if (std::numeric_limits<std::uint32_t>::max() - lookahead <= index)
        return std::numeric_limits<std::uint32_t>::max();
      return index + lookahead;
    }

    cryptonote::network_type convert_net_type(const Monero::NetworkType in)
    {
      switch(in)
      {
      case Monero::NetworkType::MAINNET:
        return cryptonote::network_type::MAINNET;
      case Monero::NetworkType::TESTNET:
        return cryptonote::network_type::TESTNET;
      case Monero::NetworkType::STAGENET:
        return cryptonote::network_type::STAGENET;
      default:
        break;
      }
      return cryptonote::network_type::UNDEFINED;
    }

    bool is_tx_spendtime_unlocked(const std::uint64_t chain_height, const std::uint64_t unlock_time, const std::uint64_t block_height, Monero::NetworkType nettype_in)
    {
      const auto nettype = convert_net_type(nettype_in);
      if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
      {
        //interpret as block index
        if(chain_height - 1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
          return true;
        else
          return false;
      }else
      {
        //interpret as time
        const uint64_t adjusted_time = std::time(nullptr);
        // XXX: this needs to be fast, so we'd need to get the starting heights
        // from the daemon to be correct once voting kicks in
        uint64_t v2height = nettype == cryptonote::TESTNET ? 624634 : nettype == cryptonote::STAGENET ? 32000  : 1009827;
        uint64_t leeway = chain_height < v2height ? CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1 : CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2;
        if(adjusted_time + leeway >= unlock_time)
          return true;
        else
          return false;
      }
      return false;
    }

    crypto::secret_key get_subaddress_secret_key(const crypto::secret_key &a, const std::uint32_t major, const std::uint32_t minor)
    {
      char data[sizeof(::config::HASH_KEY_SUBADDRESS) + sizeof(crypto::secret_key) + 2 * sizeof(uint32_t)];
      memcpy(data, ::config::HASH_KEY_SUBADDRESS, sizeof(::config::HASH_KEY_SUBADDRESS));
      memcpy(data + sizeof(::config::HASH_KEY_SUBADDRESS), &a, sizeof(crypto::secret_key));
      std::uint32_t idx = SWAP32LE(major);
      memcpy(data + sizeof(::config::HASH_KEY_SUBADDRESS) + sizeof(crypto::secret_key), &idx, sizeof(uint32_t));
      idx = SWAP32LE(minor);
      memcpy(data + sizeof(::config::HASH_KEY_SUBADDRESS) + sizeof(crypto::secret_key) + sizeof(uint32_t), &idx, sizeof(uint32_t));
      crypto::secret_key m;
      crypto::hash_to_scalar(data, sizeof(data), m);
      return m;
    }

    //! \return If user requested {0,0} lookahead with no known subaddresses
    bool no_subaddresses(const epee::span<const sub_account> subaccounts, const config::lookahead lookahead) noexcept
    {
      return !lookahead.major && !lookahead.minor && subaccounts.size() == 1 && !subaccounts[0].last;
    }
 
    template<typename F, typename T>
    void map_address_book_entry(F& format, T& self)
    {
      wire::object(format,
        WIRE_FIELD(address),
        WIRE_FIELD(payment_id),
        WIRE_FIELD(description)
      );
    }

    template<typename F, typename T>
    void map_subaddress(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(label));
    }

    template<typename F, typename T>
    void map_sub_account(F& format, T& self)
    {
      // do not store server lookahead, reset on each server connection
      wire::object(format,
        wire::optional_field("detail", wire::trusted_array(std::ref(self.detail))),
        WIRE_FIELD_DEFAULTED(last, 0)
      );
    }

    template<typename F, typename T>
    void map_transfer_spend(F& format, T& self)
    {
      wire::object(format,
        WIRE_FIELD(amount),
        WIRE_FIELD(sender),
        WIRE_FIELD(tx_pub),
        WIRE_FIELD(output_pub)
      );
    }

    template<typename F, typename T>
    void map_transfer_in(F& format, T& self)
    {
      wire::object(format,
        WIRE_FIELD(global_index),
        WIRE_FIELD(amount),
        WIRE_FIELD(recipient),
        WIRE_FIELD(index),
        WIRE_OPTIONAL_FIELD(rct_mask),
        WIRE_OPTIONAL_FIELD(janus),
        WIRE_FIELD(tx_pub),
        WIRE_FIELD_DEFAULTED(unified, false)
      );
    }

    template<typename F, typename T>
    void map_transfer_out(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(address), WIRE_FIELD(amount), WIRE_FIELD(secret));
    }

    template<typename F, typename T>
    void map_transaction(F& format, T& self)
    {
      // make timestamp storage as portable as possible
      using time_point = std::chrono::system_clock::time_point;
      std::optional<std::int64_t> timestamp;
      if (self.timestamp)
        timestamp = boost::numeric_cast<std::int64_t>(self.timestamp->time_since_epoch().count());

      auto payment_id = wire::variant(std::ref(self.payment_id));
      wire::object(format,
        WIRE_FIELD(raw_bytes),
        wire::optional_field("spends", wire::trusted_array(std::ref(self.spends))),
        wire::optional_field("receives", wire::trusted_array(std::ref(self.receives))),
        wire::optional_field("transfers", wire::trusted_array(std::ref(self.transfers))),
        WIRE_FIELD(description),
        wire::optional_field("timestamp", std::ref(timestamp)),
        WIRE_FIELD(amount),
        WIRE_FIELD(fee),
        WIRE_OPTIONAL_FIELD(height),
        WIRE_FIELD(unlock_time),
        WIRE_FIELD(direction),
        WIRE_OPTION("payment_id0", rpc::empty, payment_id),
        WIRE_OPTION("payment_id8", crypto::hash8, payment_id),
        WIRE_OPTION("payment_id32", crypto::hash, payment_id),
        WIRE_FIELD(id),
        WIRE_FIELD(prefix),
        WIRE_OPTIONAL_FIELD(first),
        WIRE_FIELD(coinbase),
        WIRE_FIELD_DEFAULTED(failed, false)
      );

      if constexpr (!std::is_const<T>())
      {
        self.timestamp = std::nullopt;
        if (timestamp)
          self.timestamp = time_point{time_point::duration{boost::numeric_cast<time_point::rep>(*timestamp)}};
      }
    }
  } // anonymous

  static void read_bytes(wire::reader& source, std::pair<crypto::hash, std::shared_ptr<transaction>>& dest)
  {
    if (!dest.second)
      dest.second = std::make_shared<transaction>();
    read_bytes(source, *dest.second);
    dest.first = dest.second->id;
  }
  static void write_bytes(wire::writer& dest, const std::pair<const crypto::hash, std::shared_ptr<transaction>>& source)
  {
    if (!source.second)
      WIRE_DLOG_THROW(wire::error::schema::object, "Unexpected nullptr");
    write_bytes(dest, *source.second);
  }

  namespace 
  {
    template<typename F, typename T>
    void map_keypair(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(sec), WIRE_FIELD(pub));
    }

    template<typename F, typename T>
    void map_account(F& format, T& self)
    {
      wire::object(format,
        WIRE_FIELD(language),
        WIRE_OPTIONAL_FIELD(poly),
        wire::optional_field("addressbook", wire::trusted_array(std::ref(self.addressbook))),
        wire::optional_field("subaccounts", wire::trusted_array(std::ref(self.subaccounts))),
        wire::optional_field("txes", wire::trusted_array(std::ref(self.txes))),
        wire::optional_field("attributes", wire::trusted_array(std::ref(self.attributes))),
        WIRE_FIELD(scan_height),
        WIRE_FIELD(restore_height),
        WIRE_FIELD(requested_start),
        WIRE_FIELD_DEFAULTED(lookahead, config::default_lookahead),
        WIRE_FIELD_DEFAULTED(type, Monero::MAINNET),
        WIRE_FIELD(view),
        WIRE_FIELD(spend),
        WIRE_FIELD_DEFAULTED(generated_locally, true)
      );
    }

    template<typename F, typename T>
    void map_polyseed(F& format, T& self)
    {
      wire::object(format, WIRE_FIELD(seed), WIRE_FIELD(passphrase));
    }

    rct::key get_mask(const crypto::secret_key& view_key, const rpc::output& source)
    {
      crypto::key_derivation derived{};
      if (!crypto::generate_key_derivation(source.tx_pub_key, view_key, derived))
        throw std::runtime_error{"generate_key_derivation failure"};

      crypto::secret_key scalar{};
      crypto::derivation_to_scalar(derived, source.index, scalar);

      rct::ecdhTuple commitment{source.rct.mask};
      rct::ecdhDecode(commitment, rct::sk2rct(scalar), source.rct.type == rpc::ringct::format::recompute);

      return commitment.mask;
    } 

    rpc::address_meta update_output(transfer_in& out, const rpc::output& source, const crypto::secret_key& view_key)
    {
      out.global_index = std::uint64_t(source.global_index);
      out.amount = std::uint64_t(source.amount);
      out.recipient = source.recipient.value_or(rpc::address_meta{});
      out.index = source.index;
      out.tx_pub = source.tx_pub_key;
      out.janus = source.janus_enc;
      out.unified = source.unified;

      switch (source.rct.type)
      {
      default:
        throw std::runtime_error{"Unexpected ringct mask type"};
      case rpc::ringct::format::none:
        out.rct_mask = std::nullopt;
        break;
      case rpc::ringct::format::encrypted:
      case rpc::ringct::format::recompute:
        out.rct_mask = get_mask(view_key, source);
        break;
      case rpc::ringct::format::unencrypted:
        out.rct_mask = source.rct.mask;
        break;
      }

      return out.recipient;
    }

    rpc::address_meta update_spend(transfer_spend& out, const rpc::transaction_spend& source, const crypto::public_key& output_pub)
    {
      out.amount = std::uint64_t(source.amount);
      out.sender = source.sender.value_or(rpc::address_meta{});
      out.tx_pub = source.tx_pub_key;
      out.output_pub = output_pub;
      return out.sender;
    }

    namespace
    {
      const unsigned char* ec_to_bytes(const crypto::ec_scalar& out)
      {
        return reinterpret_cast<const unsigned char*>(out.data);
      }

      unsigned char* ec_to_bytes(crypto::ec_scalar& out)
      {
        return reinterpret_cast<unsigned char*>(out.data);
      }
    }

    crypto::secret_key get_spend_secret(const account& self, const std::optional<rpc::address_meta>& index)
    {
      if (!index || index->is_default())
        return self.spend.sec;

      // m = Hs(a || index_major || index_minor)
      const crypto::secret_key m = get_subaddress_secret_key(self.view.sec, index->maj_i, index->min_i);

      // D = B + M
      crypto::secret_key out;
      sc_add(ec_to_bytes(out), ec_to_bytes(m), ec_to_bytes(self.spend.sec));
      return out;
    }

    //! \return True if used subaddresses has been increased
    bool need_expansion(const account& self, const rpc::address_meta& sub)
    {
      if (self.subaccounts.size() <= sub.maj_i)
        return true;
      return self.subaccounts[sub.maj_i].last < sub.min_i; // last is inclusive
    }

    std::optional<std::vector<rpc::address_meta>> update_tx(const account& self, transaction& out, const rpc::transaction& source)
    {
      /* Let `receives` and `spends` re-populate in `merge_output` and
        `update_spend` respectively. This works because the server supplies all
        info - there is no local info to keep. The spend secret and address is
        kept separate in `transfers` */
      out.receives.clear();
      out.spends.clear();

      std::vector<rpc::address_meta> meta;

      out.id = source.hash;
      if (source.timestamp)
        out.timestamp = std::chrono::system_clock::from_time_t(*source.timestamp);
      else
        out.timestamp = std::nullopt;
      out.fee = std::uint64_t(source.fee.value_or(rpc::uint64_string(0)));
      out.height = source.height;
      out.unlock_time = source.unlock_time;
      out.payment_id = source.payment_id;
      out.coinbase = source.coinbase;

      std::uint64_t total_spent = 0; 
      for (const auto& spend : source.spent_outputs)
      {
        crypto::key_derivation derivation{};
        if (!crypto::generate_key_derivation(spend.tx_pub_key, self.view.sec, derivation))
          continue;

        crypto::public_key spend_pub{};
        const crypto::secret_key spend_sec = get_spend_secret(self, spend.sender);
        if (!crypto::secret_key_to_public_key(spend_sec, spend_pub))
          continue;

        crypto::public_key output_pub{};
        if (!crypto::derive_public_key(derivation, spend.out_index, spend_pub, output_pub))
          continue;

        crypto::secret_key output_secret{};
        crypto::derive_secret_key(derivation, spend.out_index, spend_sec, output_secret);

        crypto::key_image image{};
        crypto::generate_key_image(output_pub, output_secret, image);
        if (image == spend.key_image)
        {
          /* Frontend will typically know about spend before backend. So only
            merge and never erase spends. */
          const rpc::address_meta sub = update_spend(out.spends.try_emplace(image).first->second, spend, output_pub);
          if (need_expansion(self, sub))
            meta.push_back(sub);
          total_spent += std::uint64_t(spend.amount);
        }
      }

      if (!std::uint64_t(source.total_received) && !total_spent)
        return std::nullopt; // used as decoy

      if (out.fee <= total_spent)
        total_spent -= out.fee;

      if (rpc::uint64_string(total_spent) < source.total_received)
      {
        out.direction = Monero::TransactionInfo::Direction_In;
        out.amount = std::uint64_t(source.total_received) - total_spent;
      }
      else
      {
        out.direction = Monero::TransactionInfo::Direction_Out;
        out.amount = total_spent - std::uint64_t(source.total_received);
      }

      return meta;
    }

    rpc::address_meta merge_output(const std::shared_ptr<transaction>& out, const rpc::output& source, const crypto::secret_key& view_key)
    {
      if (!out)
        throw std::logic_error{"nullptr transaction in merge_output"};

      out->prefix = source.tx_prefix_hash;
      out->first = source.first_key_image;
      if (source.janus_enc && !out->first && !out->coinbase)
        return {}; // server sent invalid output
      return update_output(out->receives[source.public_key], source, view_key);
    }

    struct merge_results
    {
      std::vector<std::shared_ptr<transaction>> new_transactions;
      boost::container::flat_set<rpc::address_meta> new_subaddrs;
      std::optional<std::uint64_t> lookahead_fail;

      void merge_subaddr(const rpc::address_meta& meta)
      {
        new_subaddrs.insert(meta);
      }
    };

    merge_results merge_response(wallet& self, const rpc::get_address_txs& source, const rpc::get_unspent_outs_response& unspents)
    {
      // Remember that this function provides the strong exception guarantee.

      merge_results out;
      out.lookahead_fail = source.lookahead_fail;

      /* Backend server could remove or modify txes (rescan or bug fix); the
        easiest way to handle this is to start a new copy of the txes. This is
        what the existing (JS) MyMonero frontend does. This has the benefit
        of allowing `shared_ptr<transaction>` objects to be "given away" to
        other parts of the frontend without a mutex.

        ADDITIONALLY, the strong exception guarantee is provided by the
        `refresh()` method; the wallet is never in a partial-state. Swapping
        the transactions at the end helps with this guarantee. */

      std::unordered_map<crypto::hash, std::shared_ptr<transaction>> updated_txes;
      updated_txes.reserve(
        std::max(self.primary.txes.size(), source.transactions.size())
      );

      std::unordered_multimap<crypto::key_image, std::shared_ptr<transaction>> images;

      /* The frontend will know about the spend first, iff the frontend was
        used to perform the spend. We copy _all_ transactions that have a
        spend secret, even if the backend doesn't acknowledge it, otherwise the
        secret information will be lost in many situations. If the spend
        never gets confirmed, this will just sit in the transaction list. */
      for (const auto& tx : self.primary.txes)
      {
        if (tx.second)
        {
          const bool rescanning =
            source.scanned_block_height < tx.second->height.value_or(0);
          if (rescanning || !tx.second->description.empty() || !tx.second->transfers.empty())
          {
            const auto iter = updated_txes.emplace_hint(
              updated_txes.end(), tx.first, nullptr
            );

            if (!iter->second)
            {
              iter->second = std::make_shared<transaction>(*tx.second);
              for (const auto& spend : tx.second->spends)
                images.emplace(spend.first, iter->second);
 
              if (!rescanning)
              {
                iter->second->height = std::nullopt;
                iter->second->failed = false;
              }
            }
          }
        }
      }

      for (const auto& tx : source.transactions)
      {
        auto inserted = updated_txes.try_emplace(tx.hash, nullptr);
        if (inserted.second)
        {
          const auto existing = self.primary.txes.find(tx.hash);
          if (existing != self.primary.txes.end() && existing->second)
            inserted.first->second = std::make_shared<transaction>(*existing->second);
          else
            inserted.first->second = std::make_shared<transaction>();

          if (existing == self.primary.txes.end())
            out.new_transactions.push_back(inserted.first->second);
        }
        if (const auto subs = update_tx(self.primary, *inserted.first->second, tx))
        {
          for (const auto& sub : *subs)
            out.merge_subaddr(sub);

          for (const auto& spend : inserted.first->second->spends)
          {
            for (auto range = images.equal_range(spend.first); range.first != range.second; ++range.first)
            {
              if (inserted.first->second->id != range.first->second->id)
                range.first->second->failed = true;
            }
          }
        }
        else
          updated_txes.erase(tx.hash);
      }

      for (const auto& output : unspents.outputs)
      {
        auto iter = updated_txes.find(output.tx_hash);
        if (iter != updated_txes.end())
        {
          const auto sub = merge_output(iter->second, output, self.primary.view.sec);
          if (need_expansion(self.primary, sub))
            out.merge_subaddr(sub);
        }
      } 

      // don't touch `self` until end to provide strong exception guarantee

      // update our "used" records immediately, server already knows about them.
      // udpate "serer_lookahead" values later, we force lookahead from zero
      for (const auto& sub : out.new_subaddrs)
      {
        if (std::numeric_limits<std::size_t>::max() <= sub.maj_i)
          throw std::runtime_error{"merge_response exceeded max size_t value"};
        if (self.primary.subaccounts.size() <= sub.maj_i)
          self.primary.subaccounts.resize(std::size_t(sub.maj_i) + 1);

        auto& acct = self.primary.subaccounts.at(sub.maj_i);
        acct.last = std::max(acct.last, sub.min_i);
      }

      // Update txes _after_ subaccounts table
      self.primary.txes.swap(updated_txes);

      self.blockchain_height = source.blockchain_height;
      self.primary.restore_height = source.start_height;
      self.primary.requested_start = std::min(self.primary.requested_start, self.primary.restore_height);
      self.primary.scan_height = source.scanned_block_height;
      self.server_lookahead.major = source.lookahead.maj_i;
      self.server_lookahead.minor = source.lookahead.min_i;

      if (self.primary.restore_height <= self.primary.requested_start && !source.lookahead_fail) 
        self.import_error = {};

      self.fee_mask = unspents.fee_mask;
      if (unspents.fees.empty())
      {
        self.per_byte_fee.resize(1);
        self.per_byte_fee[0] = unspents.per_byte_fee;
      }
      else
        self.per_byte_fee = std::move(unspents.fees);

      return out;
    }

    std::error_code handle_subaddress_error(std::error_code error) noexcept
    {
      if (error == rpc_max_subaddresses)
        error = {error::subaddr_ahead};
      else if (error == rpc_not_implemented)
        error = {error::subaddr_disabled};
      else if (error == wire::error::schema::array_max_element)
        error = {error::subaddr_local};
 
      return error;
    }

    void prep_primary_account(sub_account& self)
    {
      // Enforce special account {0,0} exists and is labeled
      self.detail.try_emplace(0).first->second.label = std::string{config::default_primary_name};
      self.last = 0;
    }

    bool should_attempt_rescan(const account& self, boost::container::flat_map<std::uint32_t, rpc::subaddrs> subaddrs, const std::uint64_t max_subaddresses)
    {
      return self.needed_subaddresses(std::move(subaddrs)) <= max_subaddresses;
    }

    template<typename F>
    void prep_subs(std::shared_ptr<wallet> self, rpc::login&& creds, const boost::optional<rpc::address_meta>& force_lookahead, F f)
    { 
      struct frame
      {
        const std::weak_ptr<wallet> self;
        F f;
        rpc::upsert_subaddrs_request request;
        rpc::upsert_subaddrs_response response;

        frame(std::shared_ptr<wallet>&& self, rpc::login&& creds, F&& f)
          : self(std::move(self)), f(std::move(f)), request{std::move(creds)}, response{}
        {}
      };

      struct handler : boost::asio::coroutine
      {
        std::shared_ptr<frame> frame_;

        explicit handler(std::shared_ptr<frame> in)
          : boost::asio::coroutine(), frame_(std::move(in))
        {}

        void operator()(const std::error_code error = {})
        {
          LWSF_VERIFY(frame_);
          const auto self_ptr = frame_->self.lock();
          LWSF_VERIFY(self_ptr);
          wallet& self = *self_ptr;
          BOOST_ASIO_CORO_REENTER(*this)
          {
            BOOST_ASIO_CORO_YIELD rpc::invoke_async(
              self.client, frame_->request, std::addressof(frame_->response), *this
            );
            frame_->f(error);
          }
        }
      };

      LWSF_VERIFY(self);
      const auto& required_subs = self->primary.subaccounts;
      if (std::numeric_limits<std::uint32_t>::max() < required_subs.size())
        throw std::runtime_error{"prep_subs exceeded max major addresses"};

      handler runner{std::make_shared<frame>(std::move(self), std::move(creds), std::move(f))};

      const rpc::address_meta lookahead = force_lookahead.value_or(rpc::address_meta{});
      const std::uint32_t stop = add_uint32_clamp(required_subs.size(), lookahead.maj_i);
      bool needed = 2 <= stop;
      for (std::size_t i = 0; i < stop; ++i)
      {
        std::uint32_t last = i < required_subs.size() ? required_subs[i].last : 0;
        last = add_uint32_clamp(last, lookahead.min_i);
        if (last)
          runner.frame_->request.subaddrs_.emplace(std::uint32_t(i), rpc::subaddrs{last});
        needed |= bool(last);
      }

      if (!needed)
        return runner.frame_->f(std::error_code{});
      runner();
    }

    //! Bind N arguments into a callback that takes zero arguments to run
    template<typename F, typename... T>
    struct binder 
    {
      std::shared_ptr<wallet> self;
      F f;
      std::tuple<T...> args;

      template<std::size_t... I>
      void run(std::index_sequence<I...>)
      { f(std::move(std::get<I>(args))...); }

      void operator()()
      { run(std::make_index_sequence<sizeof...(T)>{}); }
    }; 

    //! Forward N arguments in a callback to be invoked on `wallet::strand
    template<typename F>
    struct callback_on_strand
    {
      std::weak_ptr<wallet> self_;
      F f_;

      template<typename... T>
      void operator()(T... args)
      {
        // Use `post` instead of `dispatch` due to locking in handlers
        const auto self = self_.lock();
        LWSF_VERIFY(self);
        boost::asio::post(
          self->strand,
          binder<F, T...>{self, std::move(f_), std::tuple<T...>(std::move(args)...)}
        );
      }
    };

    /*! The ASIO handlers in this file all use `boost::asio::coroutine` which
    is a light-weight async routine that looks traditional stack based code.
    Unfortunately, a lock must be held for many of the functions, because the
    API (basically) demands it. These handlers must release their lock before
    being called again or deadlock occurs. To get around this, we wrap all
    code needed to acquire `backend::wallet::sync` in a handler that posts to
    the strand, so the handler never calls itself directly.

    As an example, if `rpc::invoke_async` calls the handler immediately, this
    would cause deadlock, except the outter handler simply posts the
    operation to be deferred later, the lock is released, and then asio runs
    the handler in the next loop iteration. A bit gross, but this makes
    `backend::wallet::get_decoys` and `backend::wallet::send_tx` super fast
    and never blocking on anything (except briefly when queueing http stuff). */
    template<typename F>
    callback_on_strand<F> wrap(std::shared_ptr<wallet> self, F f)
    {
       return {std::move(self), std::move(f)};
    }

    //! Every "frame" has a `weak_ptr` to `backend::wallet`; this safely posts.
    template<typename F>
    void post(std::shared_ptr<wallet> self, F f)
    {
      LWSF_VERIFY(self);
      boost::asio::post(self->strand, binder<F>{self, std::move(f)});
    }
  } // anonymous

  WIRE_DEFINE_OBJECT(address_book_entry, map_address_book_entry);
  WIRE_DEFINE_OBJECT(subaddress, map_subaddress);
  WIRE_DEFINE_OBJECT(sub_account, map_sub_account);
  WIRE_DEFINE_OBJECT(transfer_spend, map_transfer_spend);
  WIRE_DEFINE_OBJECT(transfer_in, map_transfer_in);
  WIRE_DEFINE_OBJECT(transfer_out, map_transfer_out);
  WIRE_DEFINE_OBJECT(transaction, map_transaction);
  WIRE_DEFINE_OBJECT(keypair, map_keypair);
  WIRE_DEFINE_OBJECT(account::polyseed, map_polyseed);
  void read_bytes(wire::reader& source, account& dest)
  {
    map_account(source, dest);
    dest.address = cryptonote::get_account_address_as_str(
      convert_net_type(dest.type), false, cryptonote::account_public_address{dest.spend.pub, dest.view.pub}
    );
    if (dest.subaccounts.empty())
      prep_primary_account(dest.subaccounts.emplace_back());
  }
  void write_bytes(wire::writer& dest, const account& source)
  { map_account(dest, source); }

  std::uint64_t account::needed_subaddresses(boost::container::flat_map<std::uint32_t, rpc::subaddrs> subaddrs) const
  {
    if (this->lookahead.major == 0 || this->lookahead.minor == 0)
      return 0;

    std::uint64_t count = 0;
    const auto add_subaddresses = [&count] (const std::uint64_t next)
    {
      if (next <= std::numeric_limits<std::uint64_t>::max() - count)
        count += next;
      else
        count = std::numeric_limits<std::uint64_t>::max();
    };

    const auto count_subaddresses = [this, &add_subaddresses] (const boost::container::flat_set<std::array<std::uint32_t, 2>, std::less<>>& minors)
    {
      auto last = minors.begin();
      while (last != minors.end() && std::get<1>(*last) < this->lookahead.minor)
        ++last;

      // tally minium first, as determined by minor lookahead
      {
        std::uint64_t next = this->lookahead.minor;
        if (last != minors.end())
          next = std::max(next, std::uint64_t(std::get<1>(*last)) + 1);

        add_subaddresses(next);
      }

      // last was just included in total
      if (last != minors.end())
        ++last;

      // tally any upserted out of lookahead range
      for ( ; last != minors.end(); ++last)
        add_subaddresses(std::uint64_t(std::get<1>(*last)) - std::uint64_t(std::get<0>(*last)) + 1);
    };

    if (this->subaccounts.empty())
      throw std::runtime_error{"Subaccounts has invalid state"};

    // all registered subaddresses
    for (std::size_t i = 0; i < this->subaccounts.size(); ++i)
    {
      if (std::numeric_limits<std::uint32_t>::max() < i)
        throw std::runtime_error{"Invalid subaddress major index"};

      auto major = subaddrs.emplace(std::uint32_t(i), rpc::subaddrs{}).first;
      major->second.merge(add_uint32_clamp(this->subaccounts[i].last, this->lookahead.minor - 1));
      count_subaddresses(major->second.value);
    }

    const std::uint32_t last = 
      add_uint32_clamp(this->subaccounts.size() - 1, this->lookahead.major);
    for (std::size_t i = this->subaccounts.size(); i < last; ++i)
      add_subaddresses(this->lookahead.minor);

    // go through subaddresses after main lookahead
    for (auto elem = subaddrs.lower_bound(this->lookahead.major); elem != subaddrs.end(); ++elem)
    {
      for (const auto& minor : elem->second.value)
        add_subaddresses(std::uint64_t(std::get<1>(minor)) - std::uint64_t(std::get<0>(minor)) + 1);
    }

    return count;
  }

  sub_account::sub_account()
    : detail(), last(0)
  {}

  std::string_view sub_account::sub_label(const std::uint32_t minor) const noexcept
  {
    if (!minor)
      return primary_label();

    const auto elem = detail.find(minor);
    if (elem != detail.end())
      return elem->second.label;
    return {};
  }

  std::string_view sub_account::primary_label() const noexcept
  {
    const auto elem = detail.find(0);
    if (elem == detail.end())
      return config::default_account_name;
    return elem->second.label;
  }

  transaction::transaction()
    : raw_bytes(),
      spends(),
      receives(),
      transfers(),
      description(),
      timestamp(),
      height(),
      amount(0),
      fee(0),
      unlock_time(0),
      direction(Monero::TransactionInfo::Direction_Out),
      payment_id(),
      id{},
      prefix{},
      first(),
      coinbase(false),
      failed(false)
  {}

  transaction::transaction(const transaction& rhs)
    : raw_bytes(rhs.raw_bytes.clone()), // required because of this
      spends(rhs.spends),
      receives(rhs.receives),
      transfers(rhs.transfers),
      description(rhs.description),
      timestamp(rhs.timestamp),
      height(rhs.height),
      amount(rhs.amount),
      fee(rhs.fee),
      unlock_time(rhs.unlock_time),
      direction(rhs.direction),
      payment_id(rhs.payment_id),
      id(rhs.id),
      prefix(rhs.prefix),
      first(rhs.first),
      coinbase(rhs.coinbase),
      failed(rhs.failed)
  {}

  bool transaction::is_unlocked(const std::uint64_t chain_height, const Monero::NetworkType type) const
  {
    if (!height)
      return false;
    if(!is_tx_spendtime_unlocked(chain_height, unlock_time, *height, type))
      return false;
    if(*height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > chain_height)
      return false;
    return true;
  }

  wallet::wallet(boost::asio::io_context& io)
    : listener(nullptr),
      strand(io),
      client{},
      primary{},
      per_byte_fee(),
      login_queue(),
      refresh_queue(),
      refresh_error(),
      lookahead_error(default_subaddr_state),
      import_error(),
      last_sync(),
      blockchain_height(0),
      fee_mask(0),
      server_lookahead{},
      sync(),
      sync_listener(),
      sync_queue(),
      passed_login(false)
  {
    prep_primary_account(primary.subaccounts.emplace_back());
  }

  wallet::~wallet() noexcept {}

  void wallet::shutdown()
  {
    client.shutdown();

    const boost::lock_guard<boost::mutex> lock{sync_queue};
    login_queue.clear();
    refresh_queue.clear(); 
  }

  cryptonote::network_type wallet::get_net_type() const
  { return convert_net_type(primary.type); }

  crypto::public_key wallet::get_spend_public(const rpc::address_meta& index) const
  {
    if (index.is_default())
      return primary.spend.pub;

    // m = Hs(a || index_major || index_minor)
    crypto::secret_key m = get_subaddress_secret_key(primary.view.sec, index.maj_i, index.min_i);

    // M = m*G
    crypto::public_key M;
    crypto::secret_key_to_public_key(m, M);

    // D = B + M
    return rct::rct2pk(rct::addKeys(rct::pk2rct(primary.spend.pub), rct::pk2rct(M))); 
  }

  cryptonote::account_public_address wallet::get_spend_account(const rpc::address_meta& index) const
  {
    const bool is_subaddress = !index.is_default();
    const auto spend_public = get_spend_public(index);
    const crypto::public_key view_public = is_subaddress ?
      rct::rct2pk(rct::scalarmultKey(rct::pk2rct(spend_public), rct::sk2rct(primary.view.sec))) : primary.view.pub;
    return {spend_public, view_public};
  }

  cryptonote::account_keys wallet::get_primary_keys() const
  {
    return {
      {primary.view.pub, primary.spend.pub}, primary.spend.sec, primary.view.sec
    }; 
  }

  std::string wallet::get_spend_address(const rpc::address_meta& index) const
  { 
    return cryptonote::get_account_address_as_str(
      get_net_type(), !index.is_default(), get_spend_account(index)
    );
  }

  bool wallet::lookahead_good() const noexcept
  {
    return
      primary.lookahead.major <= server_lookahead.major &&
      primary.lookahead.minor <= server_lookahead.minor;
  }

  carrot::CarrotSelectedInput wallet::get_input(const transaction& tx, const crypto::public_key& onetime)
  {
    const bool coinbase = tx.coinbase;
    const std::uint64_t height = tx.height.value_or(0);
    const auto& input = tx.receives.at(onetime);
    const std::uint64_t amount = input.amount;

    if (input.janus)
    {
      carrot::input_context_t context;
      if (!coinbase)
      {
        LWSF_TX_VERIFY(tx.first);
        context = carrot::make_carrot_input_context(*tx.first);
      }
      else
        context = carrot::make_carrot_input_context_coinbase(height);

      mx25519_pubkey shared_unctx{};
      const auto tx_pub = carrot::raw_byte_convert<mx25519_pubkey>(input.tx_pub);

      const boost::lock_guard<boost::mutex> lock{sync};
      LWSF_TX_VERIFY(carrot::make_carrot_uncontextualized_shared_key_receiver(primary.view.sec, tx_pub, shared_unctx));

      carrot::view_tag_t view_tag{};
      carrot::make_carrot_view_tag(shared_unctx.data, context, onetime, view_tag);

      std::optional<carrot::encrypted_payment_id_t> encrypted_pid;
      const auto pid = std::get_if<crypto::hash8>(std::addressof(tx.payment_id));
      if (pid)
      {
        crypto::hash shared_ctx{};
        carrot::make_carrot_sender_receiver_secret(shared_unctx.data, tx_pub, context, shared_ctx);
        encrypted_pid = carrot::encrypt_legacy_payment_id(carrot::raw_byte_convert<carrot::payment_id_t>(*pid), shared_ctx, onetime);
      }

      if (coinbase)
      {
        return {
          amount,
          carrot::CarrotCoinbaseOutputOpeningHintV1{
            {onetime, amount, *input.janus, view_tag, tx_pub, height},
            carrot::AddressDeriveType::PreCarrot
          }
        };
      }

      return {
        amount,
        carrot::CarrotOutputOpeningHintV2{
          onetime,
          input.rct_mask.value_or(rct::identity()),
          *input.janus,
          view_tag,
          tx_pub,
          *tx.first,
          amount,
          encrypted_pid,
          {{input.recipient.maj_i, input.recipient.min_i}, carrot::AddressDeriveType::PreCarrot}
        }
      };
    }
    
    return {
      amount,
      carrot::LegacyOutputOpeningHintV1{
        onetime,
        input.tx_pub,
        {input.recipient.maj_i, input.recipient.min_i},
        amount,
        input.rct_mask.value_or(rct::identity()),
        input.index
      }
    };
  }

  bool wallet::try_scan(const carrot::CarrotEnoteV1& enote, crypto::public_key& spend)
  {
    crypto::secret_key g;
    crypto::secret_key t;
    crypto::secret_key blinding;
    rct::xmr_amount amount;
    carrot::payment_id_t pid;
    carrot::CarrotEnoteType type;
    mx25519_pubkey shared{};
    const auto tx_pub = carrot::raw_byte_convert<mx25519_pubkey>(enote.enote_ephemeral_pubkey);

    const boost::lock_guard<boost::mutex> lock{sync};
    const carrot::view_incoming_key_ram_borrowed_device view_device{primary.view.sec};
    const epee::span<const crypto::public_key> main_address{std::addressof(primary.spend.pub), 1};
    LWSF_TX_VERIFY(carrot::make_carrot_uncontextualized_shared_key_receiver(view_device, tx_pub, shared));

    // find self-sends the hard-way
    bool matched = 
      carrot::try_scan_carrot_enote_external_receiver(
        enote, std::nullopt, shared, main_address, view_device, g, t, spend, amount, blinding, pid, type 
      );

    if (!matched)
    {
      /* Enable when using view-balance keys!
      matched = carrot::try_scan_carrot_enote_internal_receiver(
        enote, *view_device, g, t, spend, amount, blinding, type, janus
      ); */
      if (!matched)
        return false;
    }
    else // external self-send (expected with legacy keys)
    {
      const carrot::input_context_t context =
        carrot::make_carrot_input_context(enote.tx_first_key_image);
    }
    return true;
  }

  std::shared_ptr<backend::transaction> wallet::make_tx(carrot::CarrotTransactionProposalV1&& proposal, const rpc::get_tree_paths_response& tree_init, const std::optional<crypto::hash8>& pid, const std::uint32_t subaddr_account)
  {
    cryptonote::network_type ctype{};
    carrot::encrypted_payment_id_t enc_pid{};
    std::vector<crypto::key_image> images;
    std::vector<fcmp_pp::OutputPair> pairs;
    std::vector<fcmp_pp::FcmpPpSalProof> proofs;
    std::vector<FcmpRerandomizedOutputCompressed> rerandomized;
    std::vector<carrot::RCTOutputEnoteProposal> enotes;
    {
      const boost::lock_guard<boost::mutex> lock{sync}; 
      ctype = get_net_type();
      const auto generate_image_device =
        std::make_shared<::carrot::generate_image_key_ram_borrowed_device>(primary.spend.sec);
      const auto view_device =
        std::make_shared<carrot::cryptonote_view_incoming_key_ram_borrowed_device>(primary.view.sec);

      const auto incoming_device =
        std::make_shared<carrot::cryptonote_view_incoming_key_ram_borrowed_device>(primary.view.sec);
      const auto generate_device =
        std::make_shared<carrot::generate_address_secret_ram_borrowed_device>(primary.spend.sec);
      const auto address_device =
        std::make_shared<carrot::carrot_hierarchy_address_device>(generate_device, primary.spend.pub, primary.view.pub);
      const carrot::key_image_device_composed image_composed{
        generate_image_device, address_device, nullptr, view_device
      };
      const carrot::cryptonote_hierarchy_address_device cryptonote_device{
        view_device, primary.spend.pub
      };

      crypto::hash tx_hash{};
      carrot::make_signable_tx_hash_from_proposal_v1(
        proposal, nullptr, view_device.get(), image_composed, tx_hash
      );

      std::vector<std::size_t> order;
      carrot::get_sorted_input_key_images_from_proposal_v1(
        proposal, image_composed, images, std::addressof(order)
      );

      LWSF_TX_VERIFY(!images.empty());
      LWSF_TX_VERIFY(order.size() == images.size());
      carrot:get_output_enote_proposals_from_proposal_v1(
        proposal, nullptr, view_device.get(), images.at(0), enotes, enc_pid
      );

      std::vector<bool> biased;
      std::vector<crypto::public_key> one_times;
      std::vector<rct::key> commitments;
      std::vector<rct::key> input_blinding;
      std::vector<rct::key> output_blinding;

      for (const auto& input : proposal.input_proposals)
      {
        biased.push_back(carrot::use_biased_hash_to_point(input));
        one_times.push_back(onetime_address_ref(input));
        commitments.push_back(amount_commitment_ref(input));
        pairs.push_back(carrot::to_output_pair(input));

        rct::xmr_amount amount;
        carrot::try_scan_opening_hint_amount(
          input,
          {std::addressof(primary.spend.pub), 1},
          view_device.get(),
          nullptr,
          amount,
          input_blinding.emplace_back()
        );
      }

      for (const auto& enote : enotes)
        output_blinding.push_back(rct::sk2rct(enote.amount_blinding_factor));

      carrot::make_carrot_rerandomized_outputs_nonrefundable(
        one_times, commitments, biased, input_blinding, output_blinding, rerandomized
      );

      LWSF_TX_VERIFY(rerandomized.size() == proposal.input_proposals.size());
      for (std::size_t i = 0; i < proposal.input_proposals.size(); ++i)
      {
        crypto::key_image ignored;
        carrot::make_sal_proof_any_to_legacy_v1(
          tx_hash, rerandomized.at(i), proposal.input_proposals.at(i), primary.spend.sec, cryptonote_device, proofs.emplace_back(), ignored
        );
      }

      tools::apply_permutation(order, rerandomized);
      tools::apply_permutation(order, pairs);
      tools::apply_permutation(order, proofs);
    } // release lock on `sync`

    const auto tree = fcmp_pp::curve_trees::curve_trees_v1();
    fcmp_pp::curve_trees::TreeCache cache(tree);

    cache.init(tree_init.top_block_height, tree_init.top_block_hash, tree_init.n_leaf_tuples, tree_init.last_path, {});
    for (const auto& path : tree_init.paths)
    {
      for (const auto& leaf : path.path.leaves)
      {
        if (cache.register_output(leaf.output_pair))
          cache.force_add_output_path(leaf.output_pair, path.leaf_idx, path.path, tree_init.n_leaf_tuples);
      }
    }

    const auto tx = tools::wallet::finalize_fcmps_and_range_proofs(
      images, rerandomized, pairs, proofs, enotes, enc_pid, proposal.fee, cache, *tree
    );

    std::unordered_set<crypto::public_key> selfs;
    for (const auto& self_send : proposal.selfsend_payment_proposals)
      selfs.emplace(self_send.proposal.destination_address_spend_pubkey);

    safe_uint64_t transfer_total{};
    for (const auto& spend : proposal.normal_payment_proposals)
      transfer_total += spend.amount;

    auto details = std::make_shared<backend::transaction>();
    details->raw_bytes = epee::byte_slice{cryptonote::t_serializable_object_to_blob(tx)};
    details->timestamp = std::chrono::system_clock::now();
    details->fee = get_tx_fee(tx);
    details->amount = transfer_total;

    details->direction = Monero::TransactionInfo::Direction_Out;
    if (pid)
      details->payment_id = *pid;
    get_transaction_hash(tx, details->id);
    get_transaction_prefix_hash(tx, details->prefix);

    LWSF_TX_VERIFY(proposal.input_proposals.size() == tx.vin.size());
    for (std::size_t i = 0; i < proposal.input_proposals.size(); ++i)
    {
      struct get_output_pub
      {
        crypto::public_key operator()(const carrot::LegacyOutputOpeningHintV1& src) const noexcept { return src.onetime_address; }
        crypto::public_key operator()(const carrot::CarrotOutputOpeningHintV1& src) const noexcept { return src.source_enote.onetime_address; }
        crypto::public_key operator()(const carrot::CarrotOutputOpeningHintV2& src) const noexcept { return src.onetime_address; }
        crypto::public_key operator()(const carrot::CarrotCoinbaseOutputOpeningHintV1& src) const noexcept { return src.source_enote.onetime_address; }
      };

      auto spend = details->spends.try_emplace(boost::get<cryptonote::txin_to_key>(tx.vin.at(i)).k_image).first;
      spend->second.output_pub = std::visit(get_output_pub{}, proposal.input_proposals.at(i));

      std::shared_ptr<backend::transaction> source;
      for (const auto& tx : primary.txes)
      {
        LWSF_TX_VERIFY(tx.second);
        for (const auto& receive : tx.second->receives)
        {
          if (receive.first == spend->second.output_pub)
          {
            source = tx.second;
            break;
          }
        }
      }
      LWSF_TX_VERIFY(source);
      const auto& base = source->receives.at(spend->second.output_pub);
      spend->second.sender = base.recipient;
      spend->second.tx_pub = base.tx_pub;
      spend->second.amount = base.amount;
    }
    
    LWSF_TX_VERIFY(enotes.size() == tx.vout.size());
    for (std::size_t i = 0; i < enotes.size(); ++i)
    {
      crypto::public_key destination{};
      const auto& enote = enotes.at(i);
      if (!try_scan(enote.enote, destination) || selfs.count(destination) == 0)
        continue;
  
      details->first = enote.enote.tx_first_key_image;
      auto receive = details->receives.try_emplace(enote.enote.onetime_address).first;
      receive->second.global_index = std::numeric_limits<std::uint64_t>::max();
      receive->second.amount = enote.amount;
      receive->second.recipient = {subaddr_account, 0};
      receive->second.index = i;
      receive->second.rct_mask = rct::sk2rct(enote.amount_blinding_factor);
      receive->second.tx_pub = carrot::raw_byte_convert<crypto::public_key>(enote.enote.enote_ephemeral_pubkey);
      receive->second.janus = enote.enote.anchor_enc;
    }

    LWSF_TX_VERIFY(1 <= enotes.size());
    for (const auto& payment : proposal.normal_payment_proposals)
    {
      const cryptonote::account_public_address dest{
        payment.destination.address_spend_pubkey, payment.destination.address_view_pubkey
      };
      const std::string address = 
        payment.destination.payment_id == carrot::payment_id_t{} ?
          cryptonote::get_account_address_as_str(ctype, payment.destination.is_subaddress, dest) :
          cryptonote::get_account_integrated_address_as_str(ctype, dest, carrot::raw_byte_convert<crypto::hash8>(payment.destination.payment_id));

      const auto context = carrot::make_carrot_input_context(enotes.at(0).enote.tx_first_key_image);
      details->transfers.emplace_back(address, payment.amount).secret =
        carrot::get_enote_ephemeral_privkey(payment, context);
    }

    return details;
  }

  expect<epee::byte_slice> wallet::to_bytes() const
  {
    epee::byte_stream dest{};
    dest.reserve(config::initial_buffer_size);

    const boost::lock_guard<boost::mutex> lock{sync};
    const std::error_code error = wire::msgpack::to_bytes(dest, primary);
    if (error)
      return error;
    return epee::byte_slice{std::move(dest)}; 
  }

  std::error_code wallet::from_bytes(epee::byte_slice source)
  {
    /* The move call shouldn't throw an exception. So either the entire
      contents of the file get loaded, or the wallet remains unchanged. */

    account reload{};
    std::error_code status = wire::msgpack::from_bytes(std::move(source), reload);
    if (!status)
    {
      const boost::lock_guard<boost::mutex> lock{sync};
      primary = std::move(reload);
      blockchain_height = primary.scan_height;
    }
    return status;
  }

  void wallet::login_is_new(std::shared_ptr<wallet> self, std::function<void(expect<bool>)> f)
  {
    struct frame
    {
      const std::weak_ptr<wallet> self;
      rpc::login_request login;
      rpc::login_response response;
      unsigned i;

      explicit frame(std::shared_ptr<wallet> in)
        : self(std::move(in)),
          login{},
          response{},
          i(0)
      {}
    };

    struct handler : boost::asio::coroutine
    {
      std::shared_ptr<frame> frame_;

      explicit handler(std::shared_ptr<frame> frame)
        : boost::asio::coroutine(), frame_(std::move(frame))
      {}

      void operator()(std::error_code error = {})
      {
        LWSF_VERIFY(frame_);
        const auto self_ptr = frame_->self.lock();
        LWSF_VERIFY(self_ptr);
        wallet& self = *self_ptr;
        assert(self.strand.running_in_this_thread());
        boost::optional<rpc::address_meta> force_lookahead;
        const boost::lock_guard<boost::mutex> lock{self.sync};

        // Remember that this function provides the strong exception guarantee.
        BOOST_ASIO_CORO_REENTER(*this)
        {
          if (self.passed_login)
            return self.run(self.login_queue, false); // not a new account

          self.passed_login = false;
          self.probed_lookahead = false;
          self.per_byte_fee.clear();
          self.fee_mask = 0;  
          self.server_lookahead = {};
          self.refresh_error = {};
          self.subaddress_error = {};
          self.import_error = {}; 
          self.lookahead_error = self.lookahead_good() ? std::error_code{} :  error::subaddr_upgrade;

          frame_->login = rpc::login_request{
            self.primary.address, self.primary.view.sec, self.primary.lookahead, true, self.primary.generated_locally
          };

          for ( ; frame_->i < 2; ++frame_->i)
          { 
            BOOST_ASIO_CORO_YIELD rpc::invoke_async(
              self.client, frame_->login, &frame_->response, wrap(self_ptr, *this)
            );

            if (error)
            {
              if (error == rpc_unapproved)
                return self.run(self.login_queue, std::error_code{error::approval});
              else if (error == rpc_internal_error)
                return self.run(self.login_queue, std::error_code{error::network_type}); // almost always this
              else if (error == rpc_not_implemented)
                return self.run(self.login_queue, std::error_code{error::create});
              else if (0 < frame_->i)
                return self.run(self.login_queue, error);
              frame_->login.lookahead = {};
            }
            else // response
            {
              self.passed_login = true;

              if (frame_->response.start_height)
              {
                self.primary.restore_height = *frame_->response.start_height;
                self.primary.requested_start = std::min(self.primary.requested_start, self.primary.restore_height);
              }

              if (frame_->response.lookahead)
              {
                self.server_lookahead = {frame_->response.lookahead->maj_i, frame_->response.lookahead->min_i};
                self.lookahead_error = {};
              }
              else
                force_lookahead = self.primary.lookahead;

              if (config::use_subaddresses)
              {
                /* Make sure all registered subs are known to this backend. This can
                  differ from lookahead because API allows arbitrary major,minor
                  requests to be performed. */
                BOOST_ASIO_CORO_YIELD prep_subs(
                  self_ptr, {frame_->login.address, frame_->login.view_key}, force_lookahead, wrap(self_ptr, *this)
                );

                if (error && !self.subaddress_error)
                  self.subaddress_error = handle_subaddress_error(error);
              }

              break; // retry loop
            }
          }

          if (!self.lookahead_good() && !self.lookahead_error)
            self.lookahead_error = {error::subaddr_ahead};
          self.run(self.login_queue, frame_->response.new_address);
        }
      }
    };

    // Post in case of nested callback
    LWSF_VERIFY(self);
    if (self->push(self->login_queue, std::move(f)))
      post(self, handler{std::make_shared<frame>(self)});
  }
 
  void wallet::refresh(std::shared_ptr<wallet> self, const bool mandatory, std::function<void(std::error_code)> f)
  {
    // everything used across async calls
    struct frame
    {
      std::weak_ptr<wallet> self;
      rpc::login login;
      rpc::get_address_txs txs_response;
      rpc::get_unspent_outs_response outs_response;
      rpc::get_version info;
      rpc::get_subaddrs subaddrs;
      merge_results merged;
      std::uint64_t orig_scan_height;
      const bool mandatory;

      explicit frame(std::shared_ptr<wallet> in, const bool mandatory)
        : self(std::move(in)),
          login{},
          txs_response{},
          outs_response{},
          info{},
          subaddrs{},
          merged{},
          orig_scan_height(0),
          mandatory(mandatory)
      {}

      ~frame()
      {
        const auto self_ptr = self.lock();
        if (self_ptr)
        {
          const boost::lock_guard<boost::mutex> lock{self_ptr->sync_listener};
          if (self_ptr->listener)
            self_ptr->listener->refreshed();
        }
      }
    }; 
    
    struct handler : boost::asio::coroutine
    {
      std::shared_ptr<frame> frame_;

      explicit handler(std::shared_ptr<frame> in)
        : boost::asio::coroutine(), frame_(std::move(in))
      {}

      void operator()(std::error_code error = {})
      {
        LWSF_VERIFY(frame_);
        const auto self_ptr = frame_->self.lock();
        LWSF_VERIFY(self_ptr);

        bool import_called = false;
        std::uint64_t from_height = 0;

        wallet& self = *self_ptr;
        assert(self.strand.running_in_this_thread());
        boost::unique_lock<boost::mutex> lock{self.sync};
        BOOST_ASIO_CORO_REENTER(*this)
        {
          {
            const auto now = std::chrono::steady_clock::now();
            if (!frame_->mandatory)
            {
              if (now - self.last_sync < config::refresh_interval_min)
                return self.run(self.refresh_queue, self.refresh_error);
            }
            self.last_sync = now;
          }

          if (!self.passed_login)
          {
            BOOST_ASIO_CORO_YIELD login(self_ptr, wrap(self_ptr, *this));
            if (error)
              return self.run(self.refresh_queue, self.refresh_error = error);
          }

          frame_->orig_scan_height = self.primary.scan_height;
          frame_->login = rpc::login{self.primary.address, self.primary.view.sec};
          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client, frame_->login, std::addressof(frame_->txs_response), wrap(self_ptr, *this)
          );

          if (error)
          {
            self.passed_login = false;
            if (error == rpc_unapproved)
              return self.run(self.refresh_queue, self.refresh_error = error::approval);
            return self.run(self.refresh_queue, self.refresh_error = error);
          }

          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client,
            rpc::get_unspent_outs_request{frame_->login, rpc::uint64_string(0), 0, true},
            std::addressof(frame_->outs_response),
            wrap(self_ptr, *this)
          );

          if (error)
          {
            self.passed_login = false;
            return self.run(self.refresh_queue, self.refresh_error = error);
          }

          // Remember that this function provides the strong exception guarantee.
          frame_->merged = merge_response(self, frame_->txs_response, frame_->outs_response);

          if (!self.import_error && self.primary.requested_start < self.primary.restore_height)
          {
            BOOST_ASIO_CORO_YIELD restore_height(
              self_ptr, self.primary.requested_start, wrap(self_ptr, *this)
            );
            import_called = true;
          }

          if (config::use_subaddresses && !import_called && (frame_->merged.lookahead_fail || !self.lookahead_good()))
          {
            if (!self.lookahead_error)
              self.lookahead_error = {error::subaddr_ahead};
            if (!self.probed_lookahead)
            {
              self.probed_lookahead = true; // block re-attempts temporarily
              BOOST_ASIO_CORO_YIELD rpc::invoke_async(
                self.client, rpc::empty{}, std::addressof(frame_->info), wrap(self_ptr, *this)
              );

              if (error == http::error(404))
                error = {lwsf::error::subaddr_upgrade};

              if (!error)
              {
                BOOST_ASIO_CORO_YIELD rpc::invoke_async(
                  self.client, frame_->login, std::addressof(frame_->subaddrs), wrap(self_ptr, *this)
                );

                if (!error && should_attempt_rescan(self.primary, std::move(frame_->subaddrs.all_subaddrs), frame_->info.max_subaddresses))
                {
                  from_height = frame_->merged.lookahead_fail.value_or(self.primary.requested_start);
                  BOOST_ASIO_CORO_YIELD restore_height(self_ptr, from_height, wrap(self_ptr, *this));
                  if (!error && self.lookahead_good())
                    self.probed_lookahead = false; // run again if/when restore_height fails during scanning
                  error = {}; // restore_height` updated `import_error`
                }
              }

              // collect all errors from above
              if (error)
                self.lookahead_error = error;
            }
          }
          else if (config::use_subaddresses && self.lookahead_good())
          {
            self.lookahead_error = {};
            self.probed_lookahead = false;
            if (self.primary.restore_height <= self.primary.requested_start)
              self.import_error = {};
          }


          // return error if subaddresses enabled, and recovered wallet
          frame_->self.reset(); // release before acquiring `sync_listener`.
          const std::error_code rc = self.refresh_error =
            self.import_error ? 
              self.import_error : self.subaddress_error ?
                self.subaddress_error : self.lookahead_error;
          const boost::lock_guard<boost::mutex> lock_listener{self.sync_listener};
          if (!self.listener)
            return self.run(self.refresh_queue, rc);

          // Call listener functions without holding `sync`, in case a call is made
          // back into the library.
          const std::uint64_t new_scan_height =
            std::max(frame_->orig_scan_height, self.primary.scan_height);
          lock.unlock();

          self.listener->refreshed();
          const auto& merged = frame_->merged;
          if (!merged.new_transactions.empty() || new_scan_height - frame_->orig_scan_height)
            self.listener->updated();

          for (std::uint64_t i = frame_->orig_scan_height; i < new_scan_height; ++i)
            self.listener->newBlock(i);

          for (const auto& tx : merged.new_transactions)
          {
            const auto txid = epee::string_tools::pod_to_hex(tx->id);
            if (tx->direction == Monero::TransactionInfo::Direction_In)
            {
              if (tx->height)
                self.listener->moneyReceived(txid, tx->amount);
              else
                self.listener->unconfirmedMoneyReceived(txid, tx->amount);
            }
            else
              self.listener->moneySpent(txid, tx->amount);
          }

          self.run(self.refresh_queue, rc);
        }
      }
    };

    LWSF_VERIFY(self);
    if (self->push(self->refresh_queue, std::move(f)))
      post(self, handler{std::make_shared<frame>(self, mandatory)});
  }

  void wallet::register_subaccount(std::shared_ptr<wallet> self, const std::uint32_t maj_i, std::function<void(std::error_code)> f)
  {
    struct frame
    {
      const std::weak_ptr<wallet> self;
      const std::function<void(std::error_code)> f;
      rpc::provision_subaddrs_response response;
      const std::uint32_t maj_i;

      explicit frame(std::shared_ptr<wallet> self, std::function<void(std::error_code)>&& f, const std::uint32_t maj_i)
        : self(std::move(self)), f(std::move(f)), response{}, maj_i(maj_i)
      {}
    };

    struct handler : boost::asio::coroutine
    {
      std::shared_ptr<frame> frame_;

      explicit handler(std::shared_ptr<frame> in) noexcept
        : boost::asio::coroutine(), frame_(std::move(in))
      {}

      static rpc::provision_subaddrs_request get_request(wallet& self, const std::uint32_t maj_i)
      {
        const std::uint32_t minor_count = std::max(std::uint32_t(1), self.primary.lookahead.minor);
        return {
          rpc::login{self.primary.address, self.primary.view.sec},
          maj_i, 0, 1, minor_count, false, /* get_all */
        };
      }

      void operator()(const std::error_code error = {})
      {
        LWSF_VERIFY(frame_ && frame_->f);
        const auto self_ptr = frame_->self.lock();
        LWSF_VERIFY(self_ptr);

        wallet& self = *self_ptr;
        assert(self.strand.running_in_this_thread());
        const boost::lock_guard<boost::mutex> lock{self.sync};
        BOOST_ASIO_CORO_REENTER(*this)
        {
          LWSF_VERIFY(frame_->maj_i < self.primary.subaccounts.size());
       
          if (!self.passed_login)
          {
            BOOST_ASIO_CORO_YIELD login(self_ptr, wrap(self_ptr, *this));
            if (error)
              return frame_->f(error);
          }

          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client, get_request(self, frame_->maj_i), &frame_->response, wrap(self_ptr, *this)
          );

          if (error && !self.subaddress_error)
            self.subaddress_error = handle_subaddress_error(error);
          frame_->f(self.subaddress_error);
        }
      }
    };

    LWSF_VERIFY(config::use_subaddresses);
    LWSF_VERIFY(self);
    post(self, handler{std::make_shared<frame>(self, std::move(f), maj_i)});
  }

  void wallet::register_subaddress(std::shared_ptr<wallet> self, const std::uint32_t maj_i, const std::uint32_t min_i, std::function<void(std::error_code)> f)
  {
    struct frame
    {
      const std::weak_ptr<wallet> self;
      const std::function<void(std::error_code)> f;
      rpc::provision_subaddrs_response response;
      const std::uint32_t maj_i;
      const std::uint32_t min_i;

      frame(std::shared_ptr<wallet> self, std::uint32_t maj_i, std::uint32_t min_i, std::function<void(std::error_code)>&& f)
        : self(std::move(self)), f(std::move(f)), response{}, maj_i(maj_i), min_i(min_i)
      {}

      rpc::provision_subaddrs_request get_request(wallet& self)
      {
        const std::uint32_t needed_min_i = add_uint32_clamp(min_i, self.primary.lookahead.minor);
        const std::uint32_t needed_count = add_uint32_clamp(unsigned(1), needed_min_i);
        return {
          rpc::login{self.primary.address, self.primary.view.sec},
          maj_i, 0, 1, needed_count, false /* get_all */
        };
      }
    };

    struct handler : boost::asio::coroutine
    {
      std::shared_ptr<frame> frame_;

      explicit handler(std::shared_ptr<frame> in)
        : boost::asio::coroutine(), frame_(std::move(in))
      {}

      void operator()(const std::error_code error = {})
      {
        LWSF_VERIFY(frame_);
        const auto self_ptr = frame_->self.lock();
        LWSF_VERIFY(self_ptr);
        wallet& self = *self_ptr;
        assert(self.strand.running_in_this_thread());
        const boost::lock_guard<boost::mutex> lock{self.sync};
        BOOST_ASIO_CORO_REENTER(*this)
        { 
          if (!self.passed_login)
          {
            BOOST_ASIO_CORO_YIELD login(self_ptr, wrap(self_ptr, *this));
            if (error)
              return frame_->f(error);
          }

          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client, frame_->get_request(self), &frame_->response, wrap(self_ptr, *this)
          );
 
          if (error && !self.subaddress_error)
            self.subaddress_error = handle_subaddress_error(error);
          frame_->f(self.subaddress_error);
        }
      }
    };

    LWSF_VERIFY(config::use_subaddresses);
    LWSF_VERIFY(self);
    const boost::lock_guard<boost::mutex> lock{self->sync};
    LWSF_VERIFY(maj_i < self->primary.subaccounts.size());
    LWSF_VERIFY(min_i <= self->primary.subaccounts[maj_i].last);
    post(self, handler{std::make_shared<frame>(self, maj_i, min_i, std::move(f))});
  }

  void wallet::set_lookahead(std::shared_ptr<wallet> self, std::uint32_t major, std::uint32_t minor, std::function<void(std::error_code)> f)
  {
    LWSF_VERIFY(config::use_subaddresses);
    LWSF_VERIFY(self);
    const boost::lock_guard<boost::mutex> lock{self->sync};
    self->primary.lookahead.major = major;
    self->primary.lookahead.minor = minor;

    const std::uint64_t from_height = self->primary.scan_height;
    restore_height(std::move(self), from_height, std::move(f));
  }
 
  void wallet::restore_height_raw(std::shared_ptr<wallet> self, const std::uint64_t height, std::function<void(expect<rpc::import_response>)> f)
  {
    struct frame
    {
      const std::weak_ptr<wallet> self;
      const std::function<void(expect<rpc::import_response>)> f;
      rpc::import_response response;
      const std::uint64_t height;

      frame(std::shared_ptr<wallet> self, const std::uint64_t height, std::function<void(expect<rpc::import_response>)>&& f)
        : self(std::move(self)), f(std::move(f)), response{}, height(height)
      {}

      void done(wallet& self_ref, expect<rpc::import_response> result)
      {
        LWSF_VERIFY(f);
        if (result)
        {
          self_ref.primary.restore_height = std::min(height, self_ref.primary.restore_height);
          self_ref.import_error = {};
          if (result->lookahead)
          {
            self_ref.server_lookahead = {result->lookahead->maj_i, result->lookahead->min_i};
            self_ref.lookahead_error = {};
          }
          else
            self_ref.lookahead_error = {error::subaddr_upgrade};
        }
        else
        {
          if (result == rpc_max_subaddresses)
            self_ref.import_error = {error::subaddr_ahead};
          else
            self_ref.import_error = result.error();
        }
        f(std::move(result));
      }
    };

    struct handler : boost::asio::coroutine
    {
      std::shared_ptr<frame> frame_;

      explicit handler(std::shared_ptr<frame> in)
        : boost::asio::coroutine(), frame_(std::move(in))
      {}

      void operator()(const std::error_code error = {})
      {
        LWSF_VERIFY(frame_);
        const auto self_ptr = frame_->self.lock();
        LWSF_VERIFY(self_ptr);
        wallet& self = *self_ptr; 
        assert(self.strand.running_in_this_thread());
        const boost::lock_guard<boost::mutex> lock{self.sync};
        BOOST_ASIO_CORO_REENTER(*this)
        {
          if (!self.passed_login)
          {
            BOOST_ASIO_CORO_YIELD login(self_ptr, wrap(self_ptr, *this));
            if (error)
              return frame_->done(self, error);
          }

          if (self.primary.restore_height <= frame_->height && self.lookahead_good() && !self.lookahead_error)
            return frame_->done(self, rpc::import_response{.lookahead = rpc::address_meta{self.server_lookahead}});
  
          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client,
            rpc::import_request{{self.primary.address, self.primary.view.sec}, frame_->height, self.primary.lookahead},
            std::addressof(frame_->response),
            wrap(self_ptr, *this)
          );

          if (error)
            return frame_->done(self, error);
          else if (frame_->response.request_fulfilled)
            return frame_->done(self, std::move(frame_->response));

          const unsigned total =
            unsigned(bool(frame_->response.import_fee)) + bool(frame_->response.payment_address);
          switch (total)
          {
            default:
            case 0:
              return frame_->done(self, {error::import_pending});
            case 1:
              if (frame_->response.import_fee.value_or(rpc::uint64_string(0)) == rpc::uint64_string(0))
                return frame_->done(self, {error::import_pending});
              return frame_->done(self, {error::import_invalid});
            case 2:
              break;
          }

          cryptonote::address_parse_info info{};
          if (!cryptonote::get_account_address_from_str(info, convert_net_type(self.primary.type), *frame_->response.payment_address))
            return frame_->done(self, {error::import_invalid});
          if (info.has_payment_id && frame_->response.payment_id)
            return frame_->done(self, {error::import_invalid});
          if (frame_->response.payment_id && (frame_->response.payment_id->empty() || (frame_->response.payment_id->size() != sizeof(crypto::hash8) && frame_->response.payment_id->size() != sizeof(crypto::hash))))
            return frame_->done(self, {error::import_invalid});

      #ifdef LWSF_MASTER_ENABLE
          std::string payment_id;
          if (frame_->response.payment_id)
            payment_id = epee::to_hex::string(epee::to_span(*frame_->response.payment_id));

          std::size_t i = 0;
          for (; i < self.primary.addressbook.size(); ++i)
          {
            const bool existing =
              self.primary.addressbook[i].address == *frame_->response.payment_address &&
              self.primary.addressbook[i].payment_id == payment_id;
            if (existing)
              break;
          }

          std::string description = "Payment of " + cryptonote::print_money(*frame_->response.import_fee) + " XMR is needed to import/restore height"; 
          if (i == self.primary.addressbook.size())
            self.primary.addressbook.push_back(address_book_entry{std::move(*frame_->response.payment_address), std::move(payment_id), std::move(description)});
          else
            self.primary.addressbook[i] = address_book_entry{std::move(*frame_->response.payment_address), std::move(payment_id), std::move(description)};
      #endif
          frame_->done(self, {error::import_pending});
        }
      }
    };

    LWSF_VERIFY(self);
    post(self, handler{std::make_shared<frame>(self, height, std::move(f))});
  }

  void wallet::get_decoys(std::shared_ptr<wallet> self, rpc::get_random_outs_request&& req, std::function<decoys_callable> f)
  {
    struct frame
    {
      const std::weak_ptr<wallet> self;
      const std::function<decoys_callable> f;
      rpc::get_random_outs_request request;
      rpc::get_random_outs_response response;

      explicit frame(std::shared_ptr<wallet>&& self, rpc::get_random_outs_request&& req, std::function<decoys_callable>&& f)
        : self(std::move(self)), f(std::move(f)), request(std::move(req)), response{}
      {}
    };

    struct handler : boost::asio::coroutine
    {
      std::shared_ptr<frame> frame_;

      explicit handler(std::shared_ptr<frame> in)
        : boost::asio::coroutine(), frame_(std::move(in))
      {}

      void operator()(const std::error_code error = {})
      {
        LWSF_VERIFY(frame_);
        const auto self_ptr = frame_->self.lock();
        LWSF_VERIFY(self_ptr);

        wallet& self = *self_ptr;
        BOOST_ASIO_CORO_REENTER(*this)
        {
          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client, frame_->request, std::addressof(frame_->response), *this
          );

          if (error)
            frame_->f(error);
          else
            frame_->f(std::move(frame_->response.amount_outs));
        };
      }
    };

    handler{std::make_shared<frame>(std::move(self), std::move(req), std::move(f))}();
  }

  void wallet::get_tree_paths(std::shared_ptr<wallet> self, rpc::get_tree_paths_request&& req, std::function<paths_callable> f)
  {
    struct frame
    {
      const std::weak_ptr<wallet> self;
      const std::function<paths_callable> f;
      const rpc::get_tree_paths_request request;
      rpc::get_tree_paths_response response;

      explicit frame(std::shared_ptr<wallet>&& self, rpc::get_tree_paths_request&& req, std::function<paths_callable>&& f)
        : self(std::move(self)), f(std::move(f)), request(std::move(req)), response{}
      {}
    };

    struct handler : boost::asio::coroutine
    {
      std::shared_ptr<frame> frame_;

      explicit handler(std::shared_ptr<frame>&& in)
        : frame_(std::move(in))
      {}

      void operator()(const std::error_code error = {})
      {
        LWSF_VERIFY(frame_);
        const auto self_ptr = frame_->self.lock();
        LWSF_VERIFY(self_ptr);
        wallet& self = *self_ptr;
        BOOST_ASIO_CORO_REENTER(*this)
        {
          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client,
            frame_->request,
            std::addressof(frame_->response),
            *this
          );
          if (error)
            return frame_->f(error);
          return frame_->f(std::move(frame_->response));
        }
      }
    };

    handler{std::make_shared<frame>(std::move(self), std::move(req), std::move(f))}();
  }
 
  void wallet::send_tx(std::shared_ptr<wallet> self, epee::byte_slice tx_bytes, std::function<void(std::error_code)> f)
  {
    struct frame
    {
      const std::weak_ptr<wallet> self;
      const std::function<void(std::error_code)> f;
      epee::byte_slice tx_bytes;
      rpc::submit_raw_tx_response response;

      explicit frame(std::shared_ptr<wallet>&& self, epee::byte_slice&& tx_bytes, std::function<void(std::error_code)>&& f)
        : self(std::move(self)), f(std::move(f)), tx_bytes(std::move(tx_bytes)), response{}
      {}
    };

    struct handler : boost::asio::coroutine
    {
      std::shared_ptr<frame> frame_;

      explicit handler(std::shared_ptr<frame>&& in)
        : frame_(std::move(in))
      {}

      void operator()(const std::error_code error = {})
      {
        LWSF_VERIFY(frame_);
        const auto self_ptr = frame_->self.lock();
        LWSF_VERIFY(self_ptr);
        wallet& self = *self_ptr;
        BOOST_ASIO_CORO_REENTER(*this)
        {
          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client,
            rpc::submit_raw_tx_request{std::move(frame_->tx_bytes)},
            std::addressof(frame_->response),
            *this
          );
          frame_->f(error);
        }
      }
    };

    handler{std::make_shared<frame>(std::move(self), std::move(tx_bytes), std::move(f))}();
  }
}}} // lwsf // internal // backend
