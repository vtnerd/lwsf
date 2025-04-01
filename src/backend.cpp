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
      wire::object(format,
        wire::field("minor", wire::trusted_array(std::ref(self.minor)))
      );
    }

    template<typename F, typename T>
    void map_transfer_out(F& format, T& self)
    {
      wire::object(format,
        WIRE_FIELD(address),
        WIRE_FIELD(amount),
        WIRE_FIELD(sender),
        WIRE_OPTIONAL_FIELD(secret),
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
    void map_transaction(F& format, T& self)
    {
      //! TODO complete payment_id storage
      auto payment_id = wire::variant(std::ref(self.payment_id));
      wire::object(format,
        wire::field("spends", wire::trusted_array(std::ref(self.spends))),
        wire::field("receives", wire::trusted_array(std::ref(self.receives))),
        WIRE_FIELD(description),
        WIRE_OPTIONAL_FIELD(timestamp),
        WIRE_FIELD(amount),
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
  static void write_bytes(wire::writer& dest, const std::pair<crypto::hash, std::shared_ptr<transaction>>& source)
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
        wire::field("addressbook", wire::trusted_array(std::ref(self.addressbook))),
        wire::field("subaccounts", wire::trusted_array(std::ref(self.subaccounts))),
        wire::field("txes", wire::trusted_array(std::ref(self.txes))),
        wire::field("attributes", wire::trusted_array(std::ref(self.attributes))),
        WIRE_FIELD(scan_height),
        WIRE_FIELD(restore_height),
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

    void update_output(transfer_in& out, const rpc::output& source, const crypto::secret_key& view_key)
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
    }

    void update_spend(transfer_out& out, const rpc::transaction_spend& source)
    {
      out.amount = std::uint64_t(source.amount);
      out.sender = source.sender.value_or(rpc::address_meta{});
      out.tx_pub = source.tx_pub_key;
    }

    crypto::secret_key get_spend_secret(const account& self, const std::optional<rpc::address_meta>& index)
    {
      if (!index || (index->maj_i == 0 && index->min_i == 0))
        return self.spend.sec;

      // m = Hs(a || index_major || index_minor)
      const crypto::secret_key m = get_subaddress_secret_key(self.view.sec, index->maj_i, index->min_i);

      // D = B + M
      crypto::secret_key out;
      sc_add(to_bytes(out), to_bytes(m), to_bytes(self.spend.sec));
      return out;
    }

    bool update_tx(const account& self, transaction& out, const rpc::transaction& source)
    {
      /* Let `receives` re-populate in `merge_output`. This works because the
        server supplies all info - there is no local info to keep. */
      out.receives.clear();

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
          update_spend(out.spends.try_emplace(image).first->second, spend);
          total_spent += std::uint64_t(spend.amount);
        }
      }

      if (!std::uint64_t(source.total_received) && !total_spent)
        return false; // used as decoy

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

      return true;
    }

    void merge_output(const std::shared_ptr<transaction>& out, const rpc::output& source, const crypto::secret_key& view_key)
    {
      if (!out)
        throw std::logic_error{"nullptr transaction in merge_output"};

      out->prefix = source.tx_prefix_hash;
      update_output(out->receives.try_emplace(source.public_key).first->second, source, view_key);
    }

    std::vector<std::shared_ptr<transaction>>
      merge_response(wallet& self, const rpc::get_address_txs& source, const rpc::get_unspent_outs_response& unspents)
    {
      std::vector<std::shared_ptr<transaction>> out;

      /* Backend server could remove or modify txes (rescan or bug fix); the
        easiest way to handle this is to start a new copy of the txes. This is
        what the existing (JS) MyMonero frontend does. This has the benefit
        of allowing `shared_ptr<transaction>` objects to be "given away" to
        other parts of the frontend without a mutex.

        ADDITIONALLY, the strong exception guarantee is provided by the
        `refresh()` method; the wallet is never in a partial-state. Swapping
        the transactions at the end helps with this guarantee. */

      boost::container::flat_map<crypto::hash, std::shared_ptr<transaction>, memory> updated_txes;
      updated_txes.reserve(
        std::max(self.primary.txes.size(), source.transactions.size())
      );

      /* The frontend will know about the spend first, iff the frontend was
        used to perform the spend. We copy _all_ transactions that have a
        spend secret, even if the backend doesn't acknowledge it, otherwise the
        secret information will be lost in many situations. If the spend
        never gets confirmed, this will just sit in the transaction list. */
      for (const auto& tx : self.primary.txes)
      {
        if (tx.second)
        {
          for (const auto& spend : tx.second->spends)
          {
            if (spend.second.secret)
            {
              updated_txes.emplace_hint(
                updated_txes.end(), tx.first, std::make_shared<transaction>(*tx.second)
              );
              break; // inner loop
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
            out.push_back(inserted.first->second);
        }
        if (!update_tx(self.primary, *inserted.first->second, tx))
          updated_txes.erase(tx.hash);
      }

      for (const auto& output : unspents.outputs)
      {
        auto iter = updated_txes.find(output.tx_hash);
        if (iter != updated_txes.end())
          merge_output(iter->second, output, self.primary.view.sec);
      } 

      // don't touch `self` until end to provide strong exception guarantee
      self.primary.txes.swap(updated_txes);

      self.blockchain_height = source.blockchain_height;
      self.primary.restore_height = source.start_height;
      self.primary.scan_height = source.scanned_block_height;

      self.per_byte_fee = unspents.per_byte_fee;
      self.fee_mask = unspents.fee_mask;

      return out;
    }

    void merge_subaddrs(account& self, const epee::span<const rpc::subaddrs> subaddrs)
    {
      /* This will purge subaddresses that the server somehow no longer claims
      as being valid. The existing info per subaddress is moved/preserved. */

      std::map<std::uint32_t, sub_account> subaccounts;
      subaccounts.swap(self.subaccounts);

      // Never remove special {0,0} account
      self.subaccounts[0].minor[0] = std::move(subaccounts[0].minor[0]);

      for (const auto& subaddr : subaddrs)
      {
        auto& account = self.subaccounts[subaddr.key];
        auto& old = subaccounts[subaddr.key];
        for (const auto& minors : subaddr.value)
        {
          for (std::uint32_t minor = std::get<0>(minors); minor < std::uint64_t(std::get<1>(minors)) + 1; ++minor)
          {
            auto elem = account.minor.try_emplace(minor);
            if (elem.second && (subaddr.key || minor))
              elem.first->second = std::move(old.minor[minor]);
          }
        }
      }
    }
  } // anonymous

  WIRE_DEFINE_OBJECT(address_book_entry, map_address_book_entry);
  WIRE_DEFINE_OBJECT(subaddress, map_subaddress);
  WIRE_DEFINE_OBJECT(sub_account, map_sub_account);
  WIRE_DEFINE_OBJECT(transfer_out, map_transfer_out);
  WIRE_DEFINE_OBJECT(transfer_in, map_transfer_in);  
  WIRE_DEFINE_OBJECT(transaction, map_transaction);
  WIRE_DEFINE_OBJECT(keypair, map_keypair);
  void read_bytes(wire::reader& source, account& dest)
  {
    map_account(source, dest);
    dest.address = cryptonote::get_account_address_as_str(
      convert_net_type(dest.type), false, cryptonote::account_public_address{dest.spend.pub, dest.view.pub}
    );
  }
  void write_bytes(wire::writer& dest, const account& source)
  { map_account(dest, source); }

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
      last_sync(0),
      blockchain_height(0),
      fee_mask(0),
      sync()
  {
    primary.subaccounts[0].minor[0];
  }

  cryptonote::network_type wallet::get_net_type() const
  { return convert_net_type(primary.type); }

  crypto::public_key wallet::get_spend_public(const rpc::address_meta& index) const
  {
    if (index.maj_i == 0 && index.min_i == 0)
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
    return cryptonote::get_account_address_as_str(
      get_net_type(),
      (index.maj_i != 0 || index.min_i != 0),
      cryptonote::account_public_address{get_spend_public(index), primary.view.pub}
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
    {
      const rpc::login_request login{
        primary.address, primary.view.sec, true, primary.generated_locally
      };

      const auto response = rpc::invoke<rpc::login_response>(client, login);
      if (!response)
        return response.error();

      const boost::lock_guard<boost::mutex> lock{sync};
      if (response->start_height)
        primary.restore_height = *response->start_height;
    }

    const rpc::login login{primary.address, primary.view.sec};
    const auto response = rpc::invoke<rpc::get_subaddrs>(client, login);
    if (response)
    {
      const boost::lock_guard<boost::mutex> lock{sync};
      merge_subaddrs(primary, epee::to_span(response->all_subaddrs));
    }

    return {};
  }

  std::error_code wallet::refresh(const bool mandatory)
  {
    /* Remember that this function provides the strong exception guarantee.
      The state of the wallet should always be valid and never in a partially
      updated state. */

    if (!mandatory)
    {
      const auto now = std::chrono::steady_clock::now();
      const std::chrono::steady_clock::time_point start{
        std::chrono::steady_clock::time_point::duration{last_sync.load()}
      };
      if (now - start < config::refresh_interval)
        return {};
    }

    expect<rpc::get_unspent_outs_response> outs_response{common_error::kInvalidArgument};

    boost::unique_lock<boost::mutex> lock{sync};
    const auto now = std::chrono::steady_clock::now();
    if (!mandatory) // double-check
    {
      const std::chrono::steady_clock::time_point start{
        std::chrono::steady_clock::time_point::duration{last_sync.load()}
      };
      if (now - start < config::refresh_interval)
        return {};
    }
    last_sync = now.time_since_epoch().count();

    const rpc::login login{primary.address, primary.view.sec};
    lock.unlock();
    const auto txs_response = rpc::invoke<rpc::get_address_txs>(client, login);
    if (txs_response)
    {
      const rpc::get_unspent_outs_request request{login, rpc::uint64_string(0), 0, true}; 
      outs_response = rpc::invoke<rpc::get_unspent_outs_response>(client, request);
    }

    if (!txs_response)
      return txs_response.error();
    if (!outs_response)
      return outs_response.error();

    lock.lock();
    const std::uint64_t orig_scan_height = primary.scan_height;
    const auto new_txes = merge_response(*this, *txs_response, *outs_response);

    const boost::lock_guard<boost::mutex> lock2{sync_listener};
    if (!listener)
      return {};

    // Call listener functions without holding `sync`, in case a call is made
    // back into the library.
    const std::uint64_t new_scan_height =
      std::max(orig_scan_height, primary.scan_height);
    lock.unlock();

    listener->refreshed();
    if (!new_txes.empty() || new_scan_height - orig_scan_height)
      listener->updated();

    for (std::uint64_t i = orig_scan_height; i < new_scan_height; ++i)
      listener->newBlock(i);

    for (const auto& tx : new_txes)
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

    return {};
  }

  std::error_code wallet::add_subaccount(std::string label)
  {
    for (unsigned i = 0; i < config::subaddr_retry; ++i)
    {
      std::size_t next = -1;
      {
        const boost::lock_guard<boost::mutex> lock{sync};
        for (const auto& account : primary.subaccounts)
        {
          if (account.first != next + 1)
            break;
          ++next;
        }
        ++next;
      }

      if (std::numeric_limits<std::uint32_t>::max() < next)
        return {error::rpc_failure};

      const rpc::provision_subaddrs_request request{
        rpc::login{primary.address, primary.view.sec}, std::uint32_t(next), 0, 1, 1, true
      };
      const auto response = rpc::invoke<rpc::provision_subaddrs_response>(client, request);
      if (!response)
        return response.error();

      bool matched = false;
      const boost::lock_guard<boost::mutex> lock{sync};
      for (const auto& major : response->new_subaddrs)
      {
        auto& account = primary.subaccounts[major.key];
        for (const auto& minors : major.value)
        {
          for (std::uint32_t i = std::get<0>(minors); i < std::uint64_t(std::get<1>(minors)) + 1; ++i)
          {
            account.minor[i].label = std::move(label);
            label.clear();
            matched = true;
          }
        }
      }

      if (matched)
        return {};
      else
        merge_subaddrs(primary, epee::to_span(response->all_subaddrs));
    }
    return {error::rpc_failure};
  }

  std::error_code wallet::restore_height(const std::uint64_t height)
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
