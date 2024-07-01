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
#include "wire.h"
#include "wire/adapted/crypto.h"
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
        WIRE_FIELD(output_pub),
        WIRE_FIELD(rct_mask)
      );
    }
 }
    static void read_bytes(wire::reader& source, std::pair<crypto::public_key, transfer_in>& dest)
    {
      read_bytes(source, dest.second);
      dest.first = dest.second.output_pub;
    }
    static void write_bytes(wire::writer& dest, const std::pair<const crypto::public_key, transfer_in>& source)
    {
      write_bytes(dest, source.second);
    }

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
        WIRE_OPTIONAL_FIELD(tx_secret),
        WIRE_FIELD(id),
        WIRE_FIELD(coinbase)
      );
    }
}

    static void read_bytes(wire::reader& source, std::pair<crypto::hash, std::shared_ptr<transaction>>& dest)
    {
      if (!dest.second)
        dest.second = std::make_shared<transaction>(transaction{});
      read_bytes(source, *dest.second);
      dest.first = dest.second->id;
    }
    static void write_bytes(wire::writer& dest, const std::pair<const crypto::hash, std::shared_ptr<transaction>>& source)
    {
      if (!source.second)
        WIRE_DLOG_THROW(wire::error::schema::object, "Unexpected nullptr");
      write_bytes(dest, *source.second);
    }
namespace {
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
        WIRE_FIELD(spend)
      );
    }
 
    void new_tx(const account& self, transaction& out, const rpc::transaction& source)
    {
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
          out.spends.emplace_back(std::uint64_t(spend.amount), spend.tx_pub_key);
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

    void merge_output(std::shared_ptr<transaction>& out, const rpc::output& output)
    {
      if (!out)
        throw std::logic_error{"nullptr transaction in merge_output"};

      out->prefix = output.tx_prefix_hash;
      const auto receive = out->receives.lower_bound(output.public_key);
      if (receive == out->receives.end() || receive->first != output.public_key)
      {
        out->receives.emplace_hint(receive, output.public_key, transfer_in{output});
      }
    }

    bool merge_response(wallet& self, const rpc::get_address_txs& source)
    {
      bool updated_wallet = false;
      self.scan_height = source.scanned_block_height;
      self.blockchain_height = source.blockchain_height;
      self.primary.restore_height = source.start_height;

      self.primary.txes.reserve(source.transactions.size());
      for (const auto& tx : source.transactions)
      {
        auto iter = self.primary.txes.lower_bound(tx.tx_hash);
        if (iter == self.primary.txes.end() || iter->first != tx.tx_hash)
        {
          updated_wallet = true;
          new_tx(self.primary, *self.primary.txes.emplace_hint(iter, tx.tx_hash, std::make_shared<transaction>(transaction{}))->second, tx);
        }
      }
      return updated_wallet;
    }

    void merge_response(account& self, const rpc::get_unspent_outs& source)
    {
      for (const auto& output : source.outputs)
      {
        auto iter = self.txes.find(output.tx_hash);
        if (iter != self.txes.end())
          merge_output(iter->second, output);
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

  transfer_in::transfer_in()
    : global_index(0),
      amount(0),
      recipient(),
      index(0),
      output_pub{},
      rct_mask{}
  {}

  transfer_in::transfer_in(const rpc::output& source)
    : global_index(std::uint64_t(source.global_index)),
      amount(std::uint64_t(source.amount)),
      recipient(source.recipient.value_or(rpc::address_meta{})),
      index(source.index),
      output_pub(source.public_key),
      rct_mask(source.rct.mask)
  {}

  wallet::wallet(const bool generated_locally)
    : client(),
      primary{},
      status(),
      last_sync(0),
      scan_height(0),
      blockchain_height(0),
      sync(),
      generated_locally(generated_locally)
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

  expect<void> wallet::from_bytes(epee::byte_slice source)
  {
    const boost::lock_guard<boost::mutex> lock{sync};
    const std::error_code error = wire::msgpack::from_bytes(std::move(source), primary);
    if (error)
      return error;
    return success();
  }

  void wallet::refresh(const bool mandatory)
  {
    if (!mandatory)
    {
      const auto now = std::chrono::steady_clock::now();
      const std::chrono::steady_clock::time_point start{
        std::chrono::steady_clock::time_point::duration{last_sync.load()}
      };
      if (now - start < config::refresh_interval)
        return;
    }

    expect<rpc::get_unspent_outs> outs_response{common_error::kInvalidArgument};
    const rpc::login login{primary.address, primary.view.sec};
    const auto txs_response = rpc::invoke<rpc::get_address_txs>(client, login);
    if (txs_response)
      outs_response = rpc::invoke<rpc::get_unspent_outs>(client, login);

    const boost::lock_guard<boost::mutex> lock{sync};
    if (!txs_response)
    {
      status = txs_response.error();
      return;
    }
    if (!outs_response)
    {
      status = outs_response.error();
      return;
    }

    status = std::error_code{};
    merge_response(*this, *txs_response);
    merge_response(primary, *outs_response);
    last_sync = std::chrono::steady_clock::now().time_since_epoch().count();
  }
}}} // lwsf // internal // backend
