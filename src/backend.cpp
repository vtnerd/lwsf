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
#include "cryptonote_basic/cryptonote_basic_impl.h" // monero/src
#include "lwsf_config.h"
#include "ringct/rctOps.h"
#include "wire.h"
#include "wire/adapted/crypto.h"
#include "wire/adapted/pair.h"
#include "wire/msgpack.h"
#include "wire/wrapper/trusted_array.h"

namespace lwsf
{
  WIRE_AS_INTEGER(TransactionInfo::Direction);
  WIRE_AS_INTEGER(NetworkType);
}
namespace lwsf { namespace internal { namespace backend
{ 
  namespace
  {
    cryptonote::network_type convert_net_type(const NetworkType in)
    {
      switch(in)
      {
      case NetworkType::MAINNET:
        return cryptonote::network_type::MAINNET;
      case NetworkType::TESTNET:
        return cryptonote::network_type::TESTNET;
      case NetworkType::STAGENET:
        return cryptonote::network_type::STAGENET;
      default:
        break;
      }
      return cryptonote::network_type::UNDEFINED;
    }

    template<typename F, typename T>
    void map_transfer_out(F& format, T& self)
    {
      wire::object(format,
        WIRE_FIELD(address),
        WIRE_FIELD(amount),
        WIRE_FIELD(sender),
        WIRE_OPTIONAL_FIELD(secret),
        WIRE_FIELD(tx_pub)
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
  } // anonymous

  namespace 
  {
    template<typename F, typename T>
    void map_transaction(F& format, T& self)
    {
      //! TODO complete payment_id storage
      wire::object(format,
        wire::field("spends", wire::trusted_array(std::ref(self.spends))),
        wire::field("receives", wire::trusted_array(std::ref(self.receives))),
        WIRE_FIELD(description),
        WIRE_FIELD(label),
        WIRE_OPTIONAL_FIELD(timestamp),
        WIRE_FIELD(amount),
        WIRE_OPTIONAL_FIELD(height),
        WIRE_FIELD(unlock_time),
        WIRE_FIELD(direction),
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
        WIRE_FIELD(restore_height),
        wire::field("txes", wire::trusted_array(std::ref(self.txes))),
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
 
    void update_tx(const account& self, transaction& out, const rpc::transaction& source)
    {
      /* Let `receives` re-populate in `merge_output`. This works because the
        server supplies all info - there is no local info to keep. */
      out.receives.clear();

      out.id = source.tx_hash;
      out.timestamp = source.timestamp;
      out.fee = std::uint64_t(source.fee.value_or(rpc::uint64_string(0)));
      out.height = source.height;
      out.unlock_time = source.unlock_time;
      out.payment_id = source.payment_id;
      out.coinbase = source.is_coinbase;

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
        crypto::derive_secret_key(derivation, spend.out_index, self.spend.sec, output_secret);

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

      if (rpc::uint64_string(total_spent) < source.total_received)
      {
        out.direction = TransactionInfo::Direction::In;
        out.amount = std::uint64_t(source.total_received) - total_spent;
      }
      else
      {
        out.direction = TransactionInfo::Direction::Out;
        out.amount = total_spent - std::uint64_t(source.total_received);
      }
    }

    void merge_output(const std::shared_ptr<transaction>& out, const rpc::output& source, const crypto::secret_key& view_key)
    {
      if (!out)
        throw std::logic_error{"nullptr transaction in merge_output"};

      out->prefix = source.tx_prefix_hash;
      update_output(out->receives.try_emplace(source.public_key).first->second, source, view_key);
    }

    std::vector<std::shared_ptr<transaction>> merge_response(wallet& self, const rpc::get_address_txs& source)
    {
      std::vector<std::shared_ptr<transaction>> out;

      self.scan_height = source.scanned_block_height;
      self.blockchain_height = source.blockchain_height;
      self.primary.restore_height = source.start_height;

      /* Backend server could remove or modify txes (rescan or bug fix); the
        easiest way to handle this is to start a new copy of the txes. This is
        what the existing (JS) MyMonero frontend does. This has the benefit
        of allowing `shared_ptr<transaction>` objects to be "given away" to
        other parts of the frontend without a mutex. */

      const auto existing_txes = std::move(self.primary.txes);
      self.primary.txes.clear();
      self.primary.txes.reserve(
        std::max(existing_txes.size(), source.transactions.size())
      );

      /* The frontend will know about the spend first, iff the frontend was
        used to perform the spend. We copy _all_ transactions that have a
        spend secret, even if the backend doesn't acknowledge it, otherwise the
        secret information will be lost in many situations. If the spend
        never gets confirmed, this will just sit in the transaction list. */
      for (const auto& tx : existing_txes)
      {
        if (tx.second)
        {
          bool copy = false;
          for (const auto& spend : tx.second->spends)
          {
            if (spend.second.secret)
            {
              self.primary.txes.emplace_hint(
                self.primary.txes.end(), tx.first, std::make_shared<transaction>(*tx.second)
              );
              break; // inner loop
            }
          }
        }
      }

      for (const auto& tx : source.transactions)
      {
        auto inserted = self.primary.txes.try_emplace(tx.tx_hash, nullptr);
        if (inserted.second)
        {
          const auto existing = existing_txes.find(tx.tx_hash);
          try
          {
            if (existing != existing_txes.end() && existing->second)
              inserted.first->second = std::make_shared<transaction>(*existing->second);
            else
              inserted.first->second = std::make_shared<transaction>();
          }
          catch (...)
          {
            self.primary.txes.erase(inserted.first);
            throw;
          }

          if (existing != existing_txes.end())
            out.push_back(inserted.first->second);
        }
        update_tx(self.primary, *inserted.first->second, tx);
      }

      return out;
    }

    void merge_response(wallet& self, const rpc::get_unspent_outs& source)
    {
      self.per_byte_fee = source.per_byte_fee;
      self.fee_mask = source.fee_mask;
      for (const auto& output : source.outputs)
      {
        auto iter = self.primary.txes.find(output.tx_hash);
        if (iter != self.primary.txes.end())
          merge_output(iter->second, output, self.primary.view.sec);
      } 
    }
  } // anonymous

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

  wallet::wallet()
    : listener(nullptr),
      client(),
      primary{},
      last_sync(0),
      scan_height(0),
      blockchain_height(0),
      sync()
  {}

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
    const boost::lock_guard<boost::mutex> lock{sync};
    return wire::msgpack::from_bytes(std::move(source), primary);
  }

  std::error_code wallet::refresh(const bool mandatory)
  {
    if (!mandatory)
    {
      const auto now = std::chrono::steady_clock::now();
      const std::chrono::steady_clock::time_point start{
        std::chrono::steady_clock::time_point::duration{last_sync.load()}
      };
      if (now - start < config::refresh_interval)
        return {};
    }

    expect<rpc::get_unspent_outs> outs_response{common_error::kInvalidArgument};
    const rpc::login login{primary.address, primary.view.sec};
    const auto txs_response = rpc::invoke<rpc::get_address_txs>(client, login);
    if (txs_response)
      outs_response = rpc::invoke<rpc::get_unspent_outs>(client, login);

    boost::unique_lock<boost::mutex> lock{sync};

    if (!txs_response)
      return txs_response.error();
    if (!outs_response)
      return outs_response.error();

    const std::uint64_t orig_scan_height = scan_height;
    const auto new_txes = merge_response(*this, *txs_response);
    merge_response(*this, *outs_response);
    last_sync = std::chrono::steady_clock::now().time_since_epoch().count();

    if (!listener)
      return {};

    // Call listener functions without holding lock, in case a call is made
    // back into the library.
    const std::uint64_t new_scan_height = std::max(orig_scan_height, scan_height);
    lock.unlock();

    listener->refreshed();
    if (!new_txes.empty())
      listener->updated();

    for (std::uint64_t i = orig_scan_height; i < new_scan_height; ++i)
      listener->newBlock(i);

    for (const auto& tx : new_txes)
    {
      const auto txid = epee::string_tools::pod_to_hex(tx->id);
      if (tx->direction == TransactionInfo::Direction::In)
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

  std::error_code wallet::send_tx(epee::byte_slice tx_bytes)
  {
    const rpc::submit_raw_tx_request request{std::move(tx_bytes)};
    auto response = rpc::invoke<rpc::submit_raw_tx_response>(client, request);
    if (!response)
      return response.error();
    return {};
  }
}}} // lwsf // internal // backend
