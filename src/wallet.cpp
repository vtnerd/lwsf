// Copyright (c) 2014-2024, The Monero Project
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

#include "wallet.h"

#include <fstream>
#include "backend.h"
#include "hex.h"       // monero/contrib/epee/include
#include "lwsf_config.h"
#include "net/parse.h"         // monero/src
#include "net/socks_connect.h" // monero/src
#include "transaction_history.h"

namespace lwsf { namespace internal
{
  namespace
  {
    struct null_connector
    {
      boost::unique_future<boost::asio::ip::tcp::socket>
        operator()(const std::string&, const std::string&, boost::asio::steady_timer&) const
      {
        throw std::runtime_error{"Unable to connect"};
      }
    };
  }

  wallet::wallet(std::string filename, std::shared_ptr<backend::wallet> data)
    : data_(std::move(data)), filename_(std::move(filename)), thread_()
  {
    if (!data_)
      throw std::logic_error{"Unepected nullptr in internal::wallet"};
  }

  wallet::~wallet()
  {}

  void wallet::statusWithErrorString(int& status, std::string& errorString) const
  {
    const boost::unique_lock<boost::mutex> lock{data_->sync};
    status = data_->status.value();
    if (status)
      errorString = data_->status.message();
    else
      errorString.clear();
  }

  NetworkType wallet::nettype() const { data_->primary.type; }

  std::string wallet::secretViewKey() const
  {
    return epee::to_hex::string(epee::as_byte_span(unwrap(unwrap(data_->primary.view.sec))));
  }

  std::string wallet::publicViewKey() const
  {
    return epee::to_hex::string(epee::as_byte_span(data_->primary.view.pub));
  }

  std::string wallet::secretSpendKey() const
  {
    return epee::to_hex::string(epee::as_byte_span(unwrap(unwrap(data_->primary.spend.sec))));
  }

  std::string wallet::publicSpendKey() const
  {
    return epee::to_hex::string(epee::as_byte_span(data_->primary.spend.pub));
  }

  bool wallet::store(const std::string& path)
  {
    expect<epee::byte_slice> bytes = data_->to_bytes();
    if (!bytes)
      return false;

    //! \TODO Write, fsync, then atomic swap filenames

    std::ofstream file{path, std::ios::out | std::ios::binary};
    file.write(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    file.flush();
    return file.good();
  }

  bool wallet::init(const std::string &daemon_address, uint64_t, const std::string &daemon_username, const std::string &daemon_password, bool use_ssl, bool light_wallet, const std::string &proxy_address)
  {
    if (!light_wallet)
      throw std::runtime_error{"Only light_wallets are supported with this instance"};

    const auto split = daemon_address.rfind(':');
    if (!setProxy(proxy_address))
      return false; // set_status already set

    std::string host = daemon_address.substr(0, split);
    std::string port = use_ssl ? "443" : "80";
    if (split != std::string::npos)
      port = daemon_address.substr(split + 1);

    epee::net_utils::http::login login{daemon_username, daemon_password};
    const epee::net_utils::ssl_options_t options{
      use_ssl ? epee::net_utils::ssl_support_t::e_ssl_support_disabled : epee::net_utils::ssl_support_t::e_ssl_support_enabled
    };

    data_->client.set_server(std::move(host), std::move(port), std::move(login), std::move(options));

    //! \TODO Login!
    return true;
  }


  uint64_t wallet::getRefreshFromBlockHeight() const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    return data_->primary.restore_height;
  }

  bool wallet::connectToDaemon()
  {
    if (data_->client.is_connected())
      return true;
    return data_->client.connect(config::connect_timeout);
  }

  Wallet::ConnectionStatus wallet::connected() const
  {
    return data_->client.is_connected() ?
      ConnectionStatus::Connected : ConnectionStatus::Disconnected;
  }

  bool wallet::setProxy(const std::string &address)
  {
    auto endpoint = net::get_tcp_endpoint(address);
    if (!endpoint)
    {
      data_->client.set_connector(null_connector{});
      const boost::lock_guard<boost::mutex> lock{data_->sync};
      data_->status = endpoint.error();
      return false;
    }
    data_->client.set_connector(net::socks::connector{std::move(*endpoint)});
    return true;
  }

  uint64_t wallet::blockChainHeight() const
  {
    const boost::unique_lock<boost::mutex> lock{data_->sync};
    return data_->blockchain_height;
  }

  uint64_t wallet::daemonBlockChainHeight() const
  { return blockChainHeight(); }

  uint64_t wallet::daemonBlockChainTargetHeight() const
  { return blockChainHeight(); }

  
  std::shared_ptr<TransactionHistory> wallet::history()
  {
    return std::make_shared<transaction_history>(data_);
  }
}} // lwsf // internal
