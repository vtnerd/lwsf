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

#include <boost/thread/lock_guard.hpp>
#include "crypto/crypto.h"     // monero/src
#include "crypto/crypto-ops.h" // monero/src
#include "cryptonote_basic/cryptonote_basic_impl.h" // monero/src
#include "error.h"
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

namespace lwsf { namespace internal { namespace backend
{ 
  namespace
  {
    constexpr const error default_subaddr_state = error::subaddr_disabled;
    constexpr const auto rpc_unapproved = rpc::error(403);
    constexpr const auto rpc_max_subaddresses = rpc::error(409);
    constexpr const auto rpc_internal_error = rpc::error(500);
    constexpr const auto rpc_not_implemented = rpc::error(501);

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
        WIRE_FIELD_DEFAULTED(used, 0)
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
      //! TODO complete payment_id storage
      auto payment_id = wire::variant(std::ref(self.payment_id));
      wire::object(format,
        wire::optional_field("spends", wire::trusted_array(std::ref(self.spends))),
        wire::optional_field("receives", wire::trusted_array(std::ref(self.receives))),
        wire::optional_field("transfers", wire::trusted_array(std::ref(self.transfers))),
        WIRE_FIELD(description),
        WIRE_OPTIONAL_FIELD(timestamp),
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
        WIRE_FIELD(coinbase)
      );
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
        wire::optional_field("addressbook", wire::trusted_array(std::ref(self.addressbook))),
        wire::optional_field("subaccounts", wire::trusted_array(std::ref(self.subaccounts))),
        wire::optional_field("txes", wire::trusted_array(std::ref(self.txes))),
        wire::optional_field("attributes", wire::trusted_array(std::ref(self.attributes))),
        WIRE_FIELD(scan_height),
        WIRE_FIELD(restore_height),
        WIRE_FIELD_DEFAULTED(maj_lookahead, config::subaddr_major_lookahead),
        WIRE_FIELD_DEFAULTED(min_lookahead, config::subaddr_minor_lookahead),
        WIRE_FIELD(type),
        WIRE_FIELD(view),
        WIRE_FIELD(spend),
        WIRE_FIELD(generated_locally)
      );
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

    rpc::address_meta update_spend(transfer_spend& out, const rpc::transaction_spend& source)
    {
      out.amount = std::uint64_t(source.amount);
      out.sender = source.sender.value_or(rpc::address_meta{});
      out.tx_pub = source.tx_pub_key;
      return out.sender;
    }

    crypto::secret_key get_spend_secret(const account& self, const std::optional<rpc::address_meta>& index)
    {
      if (!index || index->is_default())
        return self.spend.sec;

      // m = Hs(a || index_major || index_minor)
      const crypto::secret_key m = get_subaddress_secret_key(self.view.sec, index->maj_i, index->min_i);

      // D = B + M
      crypto::secret_key out;
      sc_add(to_bytes(out), to_bytes(m), to_bytes(self.spend.sec));
      return out;
    }

    //! \return True if used subaddresses has been increased
    bool need_expansion(const account& self, const rpc::address_meta& sub)
    {
      if (self.subaccounts.size() <= sub.maj_i)
        return true;
      return self.subaccounts[sub.maj_i].used <= sub.min_i;
    }

    std::optional<std::vector<rpc::address_meta>> update_tx(const account& self, transaction& out, const rpc::transaction& source)
    {
      /* Let `receives` re-populate in `merge_output`. This works because the
        server supplies all info - there is no local info to keep. */
      out.receives.clear();

      std::vector<rpc::address_meta> meta;

      out.id = source.hash;
      out.timestamp = source.timestamp;
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
        crypto::public_key output_pub{};
        if (!crypto::derive_public_key(derivation, spend.out_index, self.spend.pub, output_pub))
          continue;
        crypto::secret_key output_secret{};
        crypto::derive_secret_key(derivation, spend.out_index, get_spend_secret(self, spend.sender), output_secret);

        crypto::key_image image{};
        crypto::generate_key_image(output_pub, output_secret, image);
        if (image == spend.key_image)
        {
          /* Frontend will typically know about spend before backend. So only
            merge and never erase spends. */
          const rpc::address_meta sub = update_spend(out.spends.try_emplace(image).first->second, spend);
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
      return update_output(out->receives[source.public_key], source, view_key);
    }

    struct merge_results
    {
      std::vector<std::shared_ptr<transaction>> new_transactions;
      boost::container::flat_set<rpc::subaddrs, std::less<>> new_subaddrs;

      void merge_subaddr(const rpc::address_meta& meta)
      {
        auto elem = new_subaddrs.find(meta.maj_i);
        if (elem == new_subaddrs.end())
          elem = new_subaddrs.insert(rpc::subaddrs{meta.maj_i}).first;

        const auto existing = elem->head;
        std::get<0>(elem->head) = std::min(std::get<0>(existing), meta.min_i);
        std::get<1>(elem->head) = std::max(std::get<1>(existing), meta.min_i);
      }
    };

    merge_results merge_response(wallet& self, const rpc::get_address_txs& source, const rpc::get_unspent_outs_response& unspents)
    {
      // Remember that this function provides the strong exception guarantee.

      merge_results out;

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
          if (!tx.second->transfers.empty())
          {
            const auto iter = updated_txes.emplace_hint(
              updated_txes.end(), tx.first, nullptr
            );
            if (!iter->second)
            {
              iter->second = std::make_shared<transaction>(*tx.second);
              iter->second->height = std::nullopt;
              iter->second->timestamp = std::nullopt;
              iter->second->failed = false;
            }
            for (const auto& spend : tx.second->spends)
              images.emplace(spend.first, iter->second);
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
              range.first->second->failed = true;
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
        if (std::numeric_limits<std::size_t>::max() <= sub.key)
          throw std::runtime_error{"merge_response exceeded max size_t value"};
        if (self.primary.subaccounts.size() <= sub.key)
          self.primary.subaccounts.resize(std::size_t(sub.key) + 1);
    
        auto& acct = self.primary.subaccounts.at(sub.key);
        acct.used = std::max(acct.used, add_uint32_clamp(unsigned(1), std::get<1>(sub.head)));
      }

      // Update txes _after_ subaccounts table
      self.primary.txes.swap(updated_txes);

      self.blockchain_height = source.blockchain_height;
      self.primary.restore_height = source.start_height;
      self.primary.scan_height = source.scanned_block_height;

      self.per_byte_fee = unspents.per_byte_fee;
      self.fee_mask = unspents.fee_mask;
      return out;
    }

    /*! Update `server_lookahead` minor fields based on `all`. The top-level
      major lookahead is set to error state if `false` is returned, and set to
      the server lookahead iff true is returned.
      \return True iff the server has enough lookahead for all fields. */
    bool update_lookaheads(wallet& self, const boost::container::flat_set<rpc::subaddrs, std::less<>>& all)
    {
      const auto maj_lookahead = self.primary.maj_lookahead;
      const auto min_lookahead = self.primary.min_lookahead;
      if (!maj_lookahead && !min_lookahead)
        throw std::logic_error{"update_lookaheads does not work with lookahead {0, 0}"};

      self.server_lookahead = {error::subaddr_server};
      const std::uint32_t server_lookahead = all.empty() ?
        std::uint32_t(0) : all.rbegin()->key;

      // Ensure major lookahead starts at zero, has no gaps, and "far" enough.
      bool min_met = add_uint32_clamp(self.primary.subaccounts.size() - 1, maj_lookahead) <= server_lookahead;
      min_met &= all.size() == std::uint64_t(server_lookahead) + 1;

      for (std::size_t i = 0; i < self.primary.subaccounts.size(); ++i)
      {
        auto& acct = self.primary.subaccounts[i];
        const auto elem = all.find(i);
        const bool has_range = elem != all.end();

        const std::uint32_t lookahead = has_range ? std::get<1>(elem->head) : 0;
        min_met &= add_uint32_clamp(acct.used, min_lookahead) <= lookahead;
        min_met &= has_range && std::get<0>(elem->head) == 0;

        // Only increase lookahead, server has no delete subaddr command
        acct.server_lookahead = std::max(acct.server_lookahead, lookahead);
      }

      // Ensure that unused minor lookahead is far enough
      for (std::size_t i = self.primary.subaccounts.size(); i < all.size(); ++i)
      {
        if (!min_met)
          break;

        const auto& range = all.nth(i)->head;
        min_met &= min_lookahead <= std::get<1>(range);
        min_met &= std::get<0>(range) == 0;
      }

      if (min_met)
        self.server_lookahead = server_lookahead;
      return min_met;
    }

    void fill_upsert(const wallet& self, boost::container::flat_set<rpc::subaddrs, std::less<>>& out)
    {
      static constexpr const std::uint32_t max_index =
        std::numeric_limits<std::uint32_t>::max();      

      const auto& accts = self.primary.subaccounts;
      const std::uint32_t minor = self.primary.min_lookahead;
      for (std::size_t i = 0; i < accts.size() && i <= max_index; ++i)
        out.insert(out.end(), rpc::subaddrs{std::uint32_t(i)})->head = {0, add_uint32_clamp(accts[i].used, minor)};

      const std::uint32_t major = add_uint32_clamp(accts.size(), self.primary.maj_lookahead);
      for (std::size_t i = accts.size(); i < major; ++i)
        out.insert(out.end(), rpc::subaddrs{std::uint32_t(i)})->head = {0, minor};
    }

    std::error_code handle_lookahead_error(std::error_code error) noexcept
    {
      if (error == rpc_max_subaddresses)
        error = {error::subaddr_server};
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
      self.used = 1;
      self.server_lookahead = 0;
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

  sub_account::sub_account()
    : detail(), used(1), server_lookahead(0)
  {}

  std::string_view sub_account::sub_label(const std::uint32_t minor) const noexcept
  {
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
    : spends(),
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

  bool transaction::is_unlocked(const std::uint64_t chain_height, const Monero::NetworkType type) const
  {
    const std::uint64_t the_height = height.value_or(std::numeric_limits<std::uint64_t>::max());
    if(!is_tx_spendtime_unlocked(chain_height, unlock_time, the_height, type))
      return false;

    if(the_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > chain_height)
      return false;

    return true;
  }

  wallet::wallet()
    : listener(nullptr),
      client(),
      primary{},
      server_lookahead(default_subaddr_state),
      last_sync(0),
      blockchain_height(0),
      per_byte_fee(0),
      fee_mask(0),
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

  std::string wallet::get_spend_address(const rpc::address_meta& index) const
  {
    const bool is_subaddress = !index.is_default();
    const auto spend_public = get_spend_public(index);
    const crypto::public_key view_public = is_subaddress ?
      rct::rct2pk(rct::scalarmultKey(rct::pk2rct(spend_public), rct::sk2rct(primary.view.sec))) : primary.view.pub;

    return cryptonote::get_account_address_as_str(
      get_net_type(),
      is_subaddress,
      cryptonote::account_public_address{spend_public, view_public}
    );
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
    }
    return status;
  }

  std::error_code wallet::login()
  {
    // Remember that this function provides the strong exception guarantee.
    boost::unique_lock<boost::mutex> lock{sync};
    {
      server_lookahead = {default_subaddr_state};
      const rpc::login_request login{
        primary.address, primary.view.sec, true, primary.generated_locally
      };

      lock.unlock();
      const auto response = rpc::invoke<rpc::login_response>(client, login);
      if (!response)
      {
        if (response == rpc_unapproved)
          return {error::approval};
        else if (response == rpc_internal_error)
          return {error::network_type}; // almost always this
        else if (response == rpc_not_implemented)
          return {error::create};
        return response.error();
      }
      lock.lock();

      passed_login = true;
      if (response->start_height)
        primary.restore_height = *response->start_height;

      if (!primary.maj_lookahead && !primary.min_lookahead)
      {
        server_lookahead = 0;
        return {};
      }
    }

    // Converting `rpc::invoke` into exceptions is easier here
    try
    {
      rpc::login login{primary.address, primary.view.sec};
      {
        lock.unlock();
        const auto response = rpc::invoke<rpc::get_subaddrs>(client, login).value();
        lock.lock();
        if (update_lookaheads(*this, response.all_subaddrs))
          return {};
      }

      // lookaheads not far enough
      rpc::upsert_subaddrs_request request{std::move(login), {}, false /* get_all */};
      fill_upsert(*this, request.subaddrs_);

      lock.unlock();
      const auto response = rpc::invoke<rpc::upsert_subaddrs_response>(client, request).value();
      lock.lock();
      update_lookaheads(*this, request.subaddrs_);
    }
    catch (const std::system_error& e)
    {
      if (e.code() == rpc_max_subaddresses)
        server_lookahead = {error::subaddr_server};
      else if (e.code() == rpc_not_implemented)
        server_lookahead = {error::subaddr_disabled};
      else if (e.code() == rpc_unapproved) // happens on new account creation
        return {error::approval};
      else if (e.code() == wire::error::schema::array_max_element)
        server_lookahead = {error::subaddr_local};
      else
        server_lookahead = e.code();
    }

    return {};
  }

  std::error_code wallet::refresh(const bool mandatory)
  {
    // Remember that this function provides the strong exception guarantee.

    if (!mandatory)
    {
      const auto now = std::chrono::steady_clock::now();
      const std::chrono::steady_clock::time_point start{
        std::chrono::steady_clock::time_point::duration{last_sync.load()}
      };
      if (now - start < config::refresh_interval_min)
        return {};
    }

    boost::unique_lock<boost::mutex> lock_refresh{sync_refresh};
    boost::unique_lock<boost::mutex> lock{sync};
    const auto now = std::chrono::steady_clock::now();
    const auto get_rc = [this, &lock] () -> std::error_code
    {
      if (!lock.owns_lock())
        lock.lock();
      if (!primary.generated_locally && (primary.maj_lookahead || primary.min_lookahead))
        return server_lookahead.error();
      return {};
    };

    if (!mandatory) // double-check
    {
      const std::chrono::steady_clock::time_point start{
        std::chrono::steady_clock::time_point::duration{last_sync.load()}
      };
      if (now - start < config::refresh_interval_min)
        return get_rc();  
    }

    struct call_refreshed
    {
      void operator()(wallet* ptr) const noexcept
      {
        if (!ptr) return;
        const boost::lock_guard<boost::mutex> lock{ptr->sync_listener};
        if (!ptr->listener) return;
        ptr->listener->refreshed();
      }
    };

    std::unique_ptr<wallet, call_refreshed> refresh_on_exit{this};
    const bool try_login = !passed_login;
    const rpc::login login{primary.address, primary.view.sec};

    lock.unlock();
    if (try_login)
    {
      const std::error_code failed_login = this->login();
      if (failed_login)
      {
        lock.lock();
        last_sync = now.time_since_epoch().count();
        return failed_login;
      }
    }

    expect<rpc::get_unspent_outs_response> outs_response{common_error::kInvalidArgument};
    const auto txs_response = rpc::invoke<rpc::get_address_txs>(client, login);
    if (txs_response)
    {
      const rpc::get_unspent_outs_request request{login, rpc::uint64_string(0), 0, true}; 
      outs_response = rpc::invoke<rpc::get_unspent_outs_response>(client, request);
    }
    lock.lock();

    last_sync = now.time_since_epoch().count();
    passed_login = bool(txs_response) && bool(outs_response); // reset state

    if (!txs_response)
    {
      if (txs_response == rpc_unapproved)
        return {error::approval};
      return txs_response.error();
    }
    if (!outs_response)
      return outs_response.error();

    const std::uint64_t orig_scan_height = primary.scan_height;
    auto merged = merge_response(*this, *txs_response, *outs_response);

    if (!merged.new_subaddrs.empty() && server_lookahead)
    {
      server_lookahead = std::max(*server_lookahead, merged.new_subaddrs.rbegin()->key);

      // ensure lookahead is from zero, or our logic is busted
      for (auto& sub : merged.new_subaddrs)
      {
        std::get<0>(sub.head) = 0;
        std::get<1>(sub.head) = add_uint32_clamp(std::get<1>(sub.head), primary.min_lookahead);
      }

      const rpc::upsert_subaddrs_request upsert_request{
        login, std::move(merged.new_subaddrs), false /* get_all */
      };

      lock.unlock();
      const auto upsert_response = rpc::invoke<rpc::upsert_subaddrs_response>(client, upsert_request);
      lock.lock();

      if (upsert_response)
      {
        for (const auto& sub : upsert_request.subaddrs_)
        {
          auto& acct = primary.subaccounts.at(sub.key);
          acct.server_lookahead = std::max(acct.server_lookahead, std::get<1>(sub.head));
        }

        if (primary.maj_lookahead)
        {
          const std::uint32_t maj_i = add_uint32_clamp(unsigned(1), upsert_request.subaddrs_.rbegin()->key);
          const std::uint32_t maj_count = primary.maj_lookahead;
          const std::uint32_t min_count = add_uint32_clamp(unsigned(1), primary.min_lookahead);
          const rpc::provision_subaddrs_request provision_request{
            login, maj_i, 0, maj_count, min_count, false /* get_all */
          };

          lock.unlock();
          const auto provision_response = rpc::invoke<rpc::provision_subaddrs_response>(client, provision_request);
          lock.lock();

          if (provision_response)
          {
            if (server_lookahead) // in case another thread jumped in
              server_lookahead = std::max(*server_lookahead, add_uint32_clamp(maj_i, maj_count - 1));
          }
          else // if !provision_response
            server_lookahead = handle_lookahead_error(provision_response.error());
        }
      }
      else // if !upsert_response
        server_lookahead = handle_lookahead_error(upsert_response.error()); 
    } // if new subaddress(es)

    // return error if subaddresses enabled, and recovered wallet
    const std::error_code rc = get_rc();
    refresh_on_exit.release(); // release before acquiring `sync_listener`.
    const boost::lock_guard<boost::mutex> lock_listener{sync_listener};
    if (!listener)
      return rc;

    // Call listener functions without holding `sync`, in case a call is made
    // back into the library.
    const std::uint64_t new_scan_height =
      std::max(orig_scan_height, primary.scan_height);
    lock.unlock();
    lock_refresh.unlock();

    listener->refreshed();
    if (!merged.new_transactions.empty() || new_scan_height - orig_scan_height)
      listener->updated();

    for (std::uint64_t i = orig_scan_height; i < new_scan_height; ++i)
      listener->newBlock(i);

    for (const auto& tx : merged.new_transactions)
    {
      const auto txid = epee::string_tools::pod_to_hex(tx->id);
      if (tx->direction == Monero::TransactionInfo::Direction_In)
      {
        if (tx->height)
          listener->moneyReceived(txid, tx->amount);
        else
          listener->unconfirmedMoneyReceived(txid, tx->amount);
      }
      else
        listener->moneySpent(txid, tx->amount);
    }

    return rc;
  }

  std::error_code wallet::add_subaccount(std::string label)
  {
    boost::unique_lock<boost::mutex> lock{sync};
    if (std::numeric_limits<std::uint32_t>::max() < primary.subaccounts.size())
      throw std::runtime_error{"wallet::add_subaccount exceeded subaddress indexes"};

    std::uint32_t maj_lookahead = 0;
    const std::uint32_t minor_count = add_uint32_clamp(unsigned(1), primary.min_lookahead); 
    for (;;)
    {
      if (!server_lookahead)
        break;

      maj_lookahead = *server_lookahead;
      const std::uint32_t maj_i = primary.subaccounts.size();
      const std::uint32_t needed_maj_lookahead = add_uint32_clamp(maj_i, primary.maj_lookahead);
      if (needed_maj_lookahead <= maj_lookahead)
        break;

      // Increase the lookahead by one
      const rpc::provision_subaddrs_request request{
        rpc::login{primary.address, primary.view.sec},
        needed_maj_lookahead, 0, 1, minor_count, false /* get_all */
      };

      lock.unlock();
      const auto response = rpc::invoke<rpc::provision_subaddrs_response>(client, request);
      lock.lock();
      if (!response)
        server_lookahead = handle_lookahead_error(response.error());

      // if NOT another call to `add_subaccount` during rpc unlock phase
      if (maj_i == primary.subaccounts.size())
      {
        if (response)
          server_lookahead = needed_maj_lookahead;
        break;
      }
    }

    // Allow account to be added if server previously had enough lookahead
    if (primary.subaccounts.size() <= maj_lookahead)
    {
      auto& maj = primary.subaccounts.emplace_back();
      maj.detail.try_emplace(0).first->second.label = std::move(label);
      maj.server_lookahead = minor_count - 1;
    }

    if (server_lookahead)
      return {};
    return server_lookahead.error();
  }

  std::error_code wallet::add_subaddress(const std::uint32_t accountIndex, std::string label)
  {
    boost::unique_lock<boost::mutex> lock{sync};
    auto maj = std::addressof(primary.subaccounts.at(accountIndex));
    if (std::numeric_limits<std::uint32_t>::max() <= maj->used)
      throw std::runtime_error{"wallet::add_subaddress exceeded subaddress indexes"};

    const std::uint32_t min_i = ++maj->used; // exceptions could leak an index :/
    const std::uint32_t needed_min_lookahead = add_uint32_clamp(min_i, primary.min_lookahead);

    if (needed_min_lookahead <= maj->server_lookahead)
    {
      maj->detail.try_emplace(min_i).first->second.label = std::move(label);
      return {};
    }

    const rpc::provision_subaddrs_request request{
      rpc::login{primary.address, primary.view.sec},
      accountIndex, 0, 1, needed_min_lookahead, false /* get_all */
    };

    lock.unlock();
    const auto response = rpc::invoke<rpc::provision_subaddrs_response>(client, request);
    lock.lock();

    // address could've changed during unlock
    maj = std::addressof(primary.subaccounts.at(accountIndex));

    if (response)
    {
      maj->server_lookahead = std::max(maj->server_lookahead, needed_min_lookahead);
      maj->detail.try_emplace(min_i - 1).first->second.label = std::move(label);
      return {};
    }
    else if (server_lookahead)
      server_lookahead = handle_lookahead_error(response.error());
    return server_lookahead.error();
  }

  std::error_code wallet::set_lookahead(std::uint32_t major, std::uint32_t minor)
  {
    boost::unique_lock<boost::mutex> lock{sync};
    const bool extending =
      primary.maj_lookahead < major ||
      primary.min_lookahead < minor;

    primary.maj_lookahead = major;
    primary.min_lookahead = minor;

    if ((!extending && server_lookahead) || (!major && !minor))
    {
      if (!server_lookahead)
        server_lookahead = 0;
      return {};
    }

    rpc::upsert_subaddrs_request request{
      rpc::login{primary.address, primary.view.sec}, {}, false /* get_all */
    };
    fill_upsert(*this, request.subaddrs_);

    lock.unlock();
    const auto response = rpc::invoke<rpc::upsert_subaddrs_response>(client, request);
    lock.lock();
    if (!response) 
      return (server_lookahead = handle_lookahead_error(response.error())).error();

    update_lookaheads(*this, request.subaddrs_);
    return {};
  }

  std::error_code wallet::restore_height(const std::uint64_t /*height not supported */)
  {
    /* TODO */
    throw std::logic_error{"restore_height not implemented"};
  }

  std::error_code wallet::send_tx(epee::byte_slice tx_bytes)
  {
    const rpc::submit_raw_tx_request request{std::move(tx_bytes)};
    auto response = rpc::invoke<rpc::submit_raw_tx_response>(client, request);
    if (!response)
      return response.error();
    return {};
  }
}}} // lwsf // internal // backend
