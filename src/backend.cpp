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

#include "backend.h"

#include <boost/asio/coroutine.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/thread/lock_guard.hpp>
#include "crypto/crypto.h"     // monero/src
#include "crypto/crypto-ops.h" // monero/src
#include "cryptonote_basic/cryptonote_basic_impl.h"   // monero/src
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "error.h"
#include "hex.h"               // monero/src
#include "lwsf_config.h"
#include "ringct/rctOps.h"
#include "wire.h"
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
        WIRE_FIELD(tx_pub)
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
        WIRE_FIELD(coinbase),
        WIRE_FIELD_DEFAULTED(failed, false)
      );

      if constexpr (!std::is_const<T>())
      {
        self.timestamp = boost::none;
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

      switch (source.rct.type)
      {
      default:
        throw std::runtime_error{"Unexpected ringct mask type"};
      case rpc::ringct::format::none:
        out.rct_mask = boost::none;
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

    crypto::secret_key get_spend_secret(const account& self, const boost::optional<rpc::address_meta>& index)
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

    boost::optional<std::vector<rpc::address_meta>> update_tx(const account& self, transaction& out, const rpc::transaction& source)
    {
      /* Let `receives` re-populate in `merge_output`. This works because the
        server supplies all info - there is no local info to keep. */
      out.receives.clear();

      std::vector<rpc::address_meta> meta;

      out.id = source.hash;
      if (source.timestamp)
        out.timestamp = std::chrono::system_clock::from_time_t(*source.timestamp);
      else
        out.timestamp = boost::none;
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
        return boost::none; // used as decoy

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
      return update_output(out->receives[source.public_key], source, view_key);
    }

    struct merge_results
    {
      std::vector<std::shared_ptr<transaction>> new_transactions;
      boost::container::flat_set<rpc::address_meta> new_subaddrs;
      boost::optional<std::uint64_t> lookahead_fail;

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
                iter->second->height = boost::none;
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
      self.primary.scan_height = source.scanned_block_height;
      self.server_lookahead.major = source.lookahead.maj_i;
      self.server_lookahead.minor = source.lookahead.min_i;

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
    void prep_subs(std::shared_ptr<wallet> self, rpc::login&& creds, F f)
    { 
      struct frame
      {
        const std::shared_ptr<wallet> self;
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
          LWSF_VERIFY(frame_ && frame_->self);
          wallet& self = *frame_->self;
          BOOST_ASIO_CORO_REENTER(*this)
          {
            BOOST_ASIO_CORO_YIELD rpc::invoke_async(
              self.client, frame_->request, std::addressof(frame_->response), std::move(*this)
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

      bool needed = 1 < required_subs.size();
      for (std::size_t i = 0; i < required_subs.size(); ++i)
      {
        const std::uint32_t last = required_subs[i].last;
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
      { f(std::move(std::get<I>(args)...)); }

      void operator()()
      { run(std::make_index_sequence<sizeof...(T)>{}); }
    }; 

    //! Forward N arguments in a callback to be invoked on `wallet::strand
    template<typename F>
    struct callback_on_strand
    {
      std::shared_ptr<wallet> self;
      F f;

      template<typename... T>
      void operator()(T... args)
      {
        // Use `post` instead of `dispatch` due to locking in handlers
        LWSF_VERIFY(self);
        boost::asio::post(
          self->strand,
          binder<F, T...>{self, std::move(f), std::tuple<T...>(std::move(args)...)}
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
    callback_on_strand<F> post_on_strand(std::shared_ptr<wallet> self, F f)
    {
       return {std::move(self), std::move(f)};
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
      refresh_error(),
      lookahead_error(default_subaddr_state),
      import_error(),
      last_sync(),
      blockchain_height(0),
      fee_mask(0),
      server_lookahead{},
      sync(),
      sync_listener(),
      sync_refresh(),
      passed_login(false)
  {
    prep_primary_account(primary.subaccounts.emplace_back());
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
      const std::shared_ptr<wallet> self;
      const std::function<void(expect<bool>)> f;
      rpc::login_request login;
      rpc::login_response response;
      unsigned i;

      explicit frame(std::shared_ptr<wallet> in, std::function<void(expect<bool>)> f)
        : self(std::move(in)),
          f(std::move(f)),
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
        LWSF_VERIFY(frame_ && frame_->self);

        // Remember that this function provides the strong exception guarantee.
        wallet& self = *frame_->self;
        assert(self.strand.running_in_this_thread());
        const boost::lock_guard<boost::mutex> lock{self.sync};
        BOOST_ASIO_CORO_REENTER(*this)
        {
          if (self.passed_login)
            return frame_->f(false); // not a new account

          self.passed_login = false;
          self.probed_lookahead = false;
          self.per_byte_fee.clear();
          self.fee_mask = 0;  
          self.server_lookahead = {};
          self.refresh_error = {};
          self.subaddress_error = {};
          self.import_error = {}; 
          self.lookahead_error = self.lookahead_good() ? std::error_code{} :  error::subaddr_disabled;

          frame_->login = rpc::login_request{
            self.primary.address, self.primary.view.sec, self.primary.lookahead, true, self.primary.generated_locally
          };

          for ( ; frame_->i < 2; ++frame_->i)
          {
            /* Do not release `lock` during login calls, want to temporarily block
              everything until complete or timeout. */

            BOOST_ASIO_CORO_YIELD rpc::invoke_async(
              self.client, frame_->login, std::addressof(frame_->response), post_on_strand(frame_->self, std::move(*this))
            );

            if (error)
            {
              if (error == rpc_unapproved)
                return frame_->f({error::approval});
              else if (error == rpc_internal_error)
                return frame_->f({error::network_type}); // almost always this
              else if (error == rpc_not_implemented)
                return frame_->f({error::create});
              else if (0 < frame_->i)
                return frame_->f(error);
              frame_->login.lookahead = {};
            }
            else // response
            {
              self.passed_login = true;

              if (frame_->response.start_height)
                self.primary.restore_height = *frame_->response.start_height;

              if (frame_->response.lookahead)
              {
                self.server_lookahead = {frame_->response.lookahead->maj_i, frame_->response.lookahead->min_i};
                self.lookahead_error = {};
              }

              /* Make sure all registered subs are known to this backend. This can
                differ from lookahead because API allows arbitrary major,minor
                requests to be performed. */
              BOOST_ASIO_CORO_YIELD prep_subs(
                frame_->self, {frame_->login.address, frame_->login.view_key}, post_on_strand(frame_->self, std::move(*this))
              );
              if (error && !self.subaddress_error)
                self.subaddress_error = handle_subaddress_error(error);

              break; // retry loop
            }
          }

          if (!self.lookahead_good() && !self.lookahead_error)
            self.lookahead_error = {error::subaddr_ahead};
          frame_->f(frame_->response.new_address);
        }
      }
    };

    // Post in case of nested callback
    LWSF_VERIFY(self);
    boost::asio::post(self->strand, handler{std::make_shared<frame>(self, std::move(f))});
  } 

  void wallet::refresh(std::shared_ptr<wallet> self, const bool mandatory, std::function<void(std::error_code)> f)
  {
    // everything used across async calls
    struct frame
    {
      std::shared_ptr<wallet> self;
      const std::function<void(std::error_code)> f;
      rpc::login login;
      rpc::get_address_txs txs_response;
      rpc::get_unspent_outs_response outs_response;
      rpc::get_version info;
      rpc::get_subaddrs subaddrs;
      merge_results merged;
      std::uint64_t orig_scan_height;
      std::uint64_t restore_height;
      boost::unique_lock<boost::mutex> lock_refresh;
      const bool mandatory;

      explicit frame(std::shared_ptr<wallet> in, std::function<void(std::error_code)>&& f, const bool mandatory)
        : self(std::move(in)),
          f(std::move(f)),
          login{},
          txs_response{},
          outs_response{},
          info{},
          subaddrs{},
          merged{},
          orig_scan_height(0),
          restore_height(0),
          lock_refresh(self->sync_refresh),
          mandatory(mandatory)
      {}

      ~frame()
      {
        if (self)
        {
          const boost::lock_guard<boost::mutex> lock{self->sync_listener};
          if (self->listener)
            self->listener->refreshed();
        }
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
        LWSF_VERIFY(frame_ && frame_->self);

        wallet& self = *frame_->self;
        assert(self.strand.running_in_this_thread());
        boost::unique_lock<boost::mutex> lock{self.sync};
        BOOST_ASIO_CORO_REENTER(*this)
        {
          {
            const auto now = std::chrono::steady_clock::now();
            if (!frame_->mandatory)
            {
              if (now - self.last_sync < config::refresh_interval_min)
                return frame_->f(self.refresh_error);
            }
            self.last_sync = now;
          }

          if (!self.passed_login)
          {
            BOOST_ASIO_CORO_YIELD login(frame_->self, post_on_strand(frame_->self, std::move(*this)));
            if (error)
              return frame_->f(self.refresh_error = error);
          }

          frame_->orig_scan_height = self.primary.scan_height;
          frame_->login = rpc::login{self.primary.address, self.primary.view.sec};
          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client, frame_->login, std::addressof(frame_->txs_response), post_on_strand(frame_->self, std::move(*this))
          );

          if (error)
          {
            self.passed_login = false;
            if (error == rpc_unapproved)
              return frame_->f(self.refresh_error = error::approval);
            return frame_->f(self.refresh_error = error);
          }

          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client,
            rpc::get_unspent_outs_request{frame_->login, rpc::uint64_string(0), 0, true},
            std::addressof(frame_->outs_response),
            post_on_strand(frame_->self, std::move(*this))
          );

          if (error)
          {
            self.passed_login = false;
            return frame_->f(self.refresh_error = error);
          }

          // Remember that this function provides the strong exception guarantee.
          frame_->merged = merge_response(self, frame_->txs_response, frame_->outs_response);

          if (frame_->merged.lookahead_fail || !self.lookahead_good())
          {
            if (!self.lookahead_error)
              self.lookahead_error = {error::subaddr_ahead};
            if (!self.probed_lookahead)
            {
              self.probed_lookahead = true; // check just once for re-scan
              BOOST_ASIO_CORO_YIELD rpc::invoke_async(
                self.client, rpc::empty{}, std::addressof(frame_->info), post_on_strand(frame_->self, std::move(*this))
              );

              if (!error)
              {
                BOOST_ASIO_CORO_YIELD rpc::invoke_async(
                  self.client, frame_->login, std::addressof(frame_->subaddrs), post_on_strand(frame_->self, std::move(*this))
                );

                if (!error && should_attempt_rescan(self.primary, std::move(frame_->subaddrs.all_subaddrs), frame_->info.max_subaddresses))
                {
                  frame_->restore_height =
                    frame_->merged.lookahead_fail.value_or(self.primary.restore_height);
                  BOOST_ASIO_CORO_YIELD
                    restore_height(frame_->self, frame_->restore_height, post_on_strand(frame_->self, std::move(*this)));
                }
              }
              else
                self.lookahead_error = error;
            }
          }
          else if (self.lookahead_good())
          {
            self.lookahead_error = {};
            self.probed_lookahead = false;
            if (self.primary.restore_height <= self.primary.requested_start)
              self.import_error = {};
          }

          if (!self.import_error && self.primary.requested_start < self.primary.restore_height)
          {
            BOOST_ASIO_CORO_YIELD restore_height(
              frame_->self, self.primary.requested_start, post_on_strand(frame_->self, std::move(*this))
            );
          }

          // return error if subaddresses enabled, and recovered wallet
          const std::shared_ptr<wallet> strong_count = frame_->self;
          frame_->self.reset(); // release before acquiring `sync_listener`.
          const std::error_code rc = self.refresh_error =
            self.import_error ? 
              self.import_error : self.subaddress_error ?
                self.subaddress_error : self.lookahead_error;
          const boost::lock_guard<boost::mutex> lock_listener{self.sync_listener};
          if (!self.listener)
            return frame_->f(rc);

          // Call listener functions without holding `sync`, in case a call is made
          // back into the library.
          const std::uint64_t new_scan_height =
            std::max(frame_->orig_scan_height, self.primary.scan_height);
          lock.unlock();
          frame_->lock_refresh.unlock();

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

          frame_->f(rc);
        }
      }
    };

    LWSF_VERIFY(self);
    boost::asio::post(self->strand, handler{std::make_shared<frame>(self, std::move(f), mandatory)});
  }

  void wallet::register_subaccount(std::shared_ptr<wallet> self, const std::uint32_t maj_i, std::function<void(std::error_code)> f)
  {
    struct frame
    {
      const std::shared_ptr<wallet> self;
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
        LWSF_VERIFY(frame_ && frame_->self && frame_->f);

        wallet& self = *frame_->self;
        assert(self.strand.running_in_this_thread());
        const boost::lock_guard<boost::mutex> lock{self.sync};
        BOOST_ASIO_CORO_REENTER(*this)
        {
          LWSF_VERIFY(frame_->maj_i < self.primary.subaccounts.size());
       
          if (!self.passed_login)
          {
            BOOST_ASIO_CORO_YIELD login(frame_->self, post_on_strand(frame_->self, std::move(*this)));
            if (error)
              return frame_->f(error);
          }

          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client,
            get_request(self, frame_->maj_i),
            std::addressof(frame_->response),
            post_on_strand(frame_->self, std::move(*this))
          );

          if (error && !self.subaddress_error)
            self.subaddress_error = handle_subaddress_error(error);
          frame_->f(self.subaddress_error);
        }
      }
    };

    LWSF_VERIFY(self);
    boost::asio::post(self->strand, handler{std::make_shared<frame>(self, std::move(f), maj_i)});
  }

  void wallet::register_subaddress(std::shared_ptr<wallet> self, const std::uint32_t maj_i, const std::uint32_t min_i, std::function<void(std::error_code)> f)
  {
    struct frame
    {
      const std::shared_ptr<wallet> self;
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
        LWSF_VERIFY(frame_ && frame_->self);
        wallet& self = *frame_->self;
        assert(self.strand.running_in_this_thread());
        const boost::lock_guard<boost::mutex> lock{self.sync};
        BOOST_ASIO_CORO_REENTER(*this)
        { 
          if (!self.passed_login)
          {
            BOOST_ASIO_CORO_YIELD login(frame_->self, post_on_strand(frame_->self, std::move(*this)));
            if (error)
              return frame_->f(error);
          }

          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client, frame_->get_request(self), std::addressof(frame_->response), post_on_strand(frame_->self, std::move(*this))
          );
 
          if (error && !self.subaddress_error)
            self.subaddress_error = handle_subaddress_error(error);
          frame_->f(self.subaddress_error);
        }
      }
    };

    LWSF_VERIFY(self);
    const boost::lock_guard<boost::mutex> lock{self->sync};
    LWSF_VERIFY(maj_i < self->primary.subaccounts.size());
    LWSF_VERIFY(min_i < self->primary.subaccounts[maj_i].last);
    boost::asio::post(self->strand, handler{std::make_shared<frame>(self, maj_i, min_i, std::move(f))});
  }

  void wallet::set_lookahead(std::shared_ptr<wallet> self, std::uint32_t major, std::uint32_t minor, std::function<void(std::error_code)> f)
  {
    LWSF_VERIFY(self);
    const boost::lock_guard<boost::mutex> lock{self->sync};
    self->primary.lookahead.major = major;
    self->primary.lookahead.minor = minor;

    const std::uint64_t from_height = self->primary.scan_height;
    restore_height(std::move(self), from_height, std::move(f));
  }

  void wallet::restore_height(std::shared_ptr<wallet> self, const std::uint64_t height, std::function<void(std::error_code)> f)
  {
    struct frame
    {
      const std::shared_ptr<wallet> self;
      const std::function<void(std::error_code)> f;
      rpc::import_response response;
      const std::uint64_t height;

      frame(std::shared_ptr<wallet> self, const std::uint64_t height, std::function<void(std::error_code)>&& f)
        : self(std::move(self)), f(std::move(f)), response{}, height(height)
      {}

      void done(const expect<rpc::import_response> result)
      {
        LWSF_VERIFY(self && f);
        if (result)
        {
          self->import_error = {};
          if (result->lookahead)
          {
            self->server_lookahead = {result->lookahead->maj_i, result->lookahead->min_i};
            self->lookahead_error = {};
          }
          else
            self->lookahead_error = {error::subaddr_disabled};
        }
        else
        {
          if (result == rpc_max_subaddresses)
            self->import_error = {error::subaddr_ahead};
          else
            self->import_error = result.error();
        }
        f(result.error());
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
        LWSF_VERIFY(frame_ && frame_->self);
        wallet& self = *frame_->self; 
        assert(self.strand.running_in_this_thread());
        const boost::lock_guard<boost::mutex> lock{self.sync};
        BOOST_ASIO_CORO_REENTER(*this)
        {
          if (!self.passed_login)
          {
            BOOST_ASIO_CORO_YIELD login(frame_->self, post_on_strand(frame_->self, std::move(*this)));
            if (error)
              frame_->done(error);
          }

          if (self.primary.restore_height <= frame_->height && self.lookahead_good() && !self.lookahead_error)
            return frame_->done(rpc::import_response{.lookahead = rpc::address_meta{self.server_lookahead}});
  
          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client,
            rpc::import_request{{self.primary.address, self.primary.view.sec}, frame_->height, self.primary.lookahead},
            std::addressof(frame_->response),
            post_on_strand(frame_->self, std::move(*this))
          );

          if (error || frame_->response.request_fulfilled)
            return frame_->done(error);

          const unsigned total =
            unsigned(bool(frame_->response.import_fee)) + bool(frame_->response.payment_address);
          switch (total)
          {
            default:
            case 0:
              return frame_->done({error::import_pending});
            case 1:
              if (frame_->response.import_fee.value_or(rpc::uint64_string(0)) == rpc::uint64_string(0))
                return frame_->done({error::import_pending});
              return frame_->done({error::import_invalid});
            case 2:
              break;
          }

          cryptonote::address_parse_info info{};
          if (!cryptonote::get_account_address_from_str(info, convert_net_type(self.primary.type), *frame_->response.payment_address))
            return frame_->done({error::import_invalid});
          if (info.has_payment_id && frame_->response.payment_id)
            return frame_->done({error::import_invalid});
          if (frame_->response.payment_id && (frame_->response.payment_id->empty() || (frame_->response.payment_id->size() != sizeof(crypto::hash8) && frame_->response.payment_id->size() != sizeof(crypto::hash))))
            return frame_->done({error::import_invalid});

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
          frame_->done({error::import_pending});
        }
      }
    };

    LWSF_VERIFY(self);
    boost::asio::post(self->strand, handler{std::make_shared<frame>(self, height, std::move(f))});
  }

  void wallet::get_decoys(std::shared_ptr<wallet> self, rpc::get_random_outs_request&& req, std::function<decoys_callable> f)
  {
    struct frame
    {
      const std::shared_ptr<wallet> self;
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
        LWSF_VERIFY(frame_ && frame_->self);

        wallet& self = *frame_->self;
        BOOST_ASIO_CORO_REENTER(*this)
        {
          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client, frame_->request, std::addressof(frame_->response), std::move(*this)
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

  void wallet::send_tx(std::shared_ptr<wallet> self, epee::byte_slice tx_bytes, std::function<void(std::error_code)> f)
  {
    struct frame
    {
      const std::shared_ptr<wallet> self;
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
        LWSF_VERIFY(frame_ && frame_->self);
        wallet& self = *frame_->self;
        BOOST_ASIO_CORO_REENTER(*this)
        {
          BOOST_ASIO_CORO_YIELD rpc::invoke_async(
            self.client,
            rpc::submit_raw_tx_request{std::move(frame_->tx_bytes)},
            std::addressof(frame_->response),
            std::move(*this)
          );
          frame_->f(error);
        }
      }
    };

    handler{std::make_shared<frame>(std::move(self), std::move(tx_bytes), std::move(f))}();
  }
}}} // lwsf // internal // backend
