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

#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))
  #include <fcntl.h>
#endif

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sodium/core.h>
#include <sodium/crypto_pwhash_argon2id.h>
#include <sodium/randombytes.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include "backend.h"
#include "error.h"
#include "hex.h"       // monero/contrib/epee/include
#include "lwsf_config.h"
#include "net/parse.h"         // monero/src
#include "net/socks_connect.h" // monero/src
#include "transaction_history.h"
#include "wire.h"
#include "wire/msgpack.h"

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

    struct encrypted_file
    {
      std::string cipher;        //!< Name of cipher+authentication used
      std::string pwhasher;      //!< Name of pwhasher used
      epee::byte_slice salt;     //!< Pwhashing salt
      epee::byte_slice nonce;    //!< Encryption iv/nonce
      epee::byte_slice epayload; //!< Encrypted contents
      std::uint64_t iterations;  //!< Pwhashing iterations
      std::uint32_t memory;      //!< Pwhashing memory

      encrypted_file() = delete;

      //! \pre `sodium_init()` has been called
      static epee::byte_slice get_random(const std::size_t length)
      {
        epee::byte_stream out;
        out.put_n(0, length);
        randombytes_buf(out.data(), length);
        return epee::byte_slice{std::move(out)};
      }

      static constexpr const char* pwhasher_name() noexcept
      {
        return "argon2id";
      }
      static constexpr int pwhash_algorithm() noexcept
      {
        return crypto_pwhash_argon2id_ALG_ARGON2ID13;
      }
      static constexpr std::size_t salt_size() noexcept
      {
        return crypto_pwhash_argon2id_SALTBYTES;
      }
      static constexpr std::uint64_t ops_min() noexcept { return 5; }
      static constexpr std::size_t memory_limit() noexcept { return 7 * 1024 * 1024; }
      static epee::byte_slice get_salt() { return get_random(salt_size()); }

      static constexpr const char* cipher_name() noexcept
      {
        return "chacha20-poly1305_ietf";
      }
      static constexpr unsigned long long max_size() noexcept
      {
        return crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX;
      }
      static constexpr std::size_t key_size() noexcept
      {
        return crypto_aead_chacha20poly1305_ietf_KEYBYTES;
      }
      static constexpr std::size_t tag_size() noexcept
      {
        return crypto_aead_chacha20poly1305_ietf_ABYTES;
      }
      static constexpr std::size_t nonce_size() noexcept
      {
        return crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
      } 
      static epee::byte_slice get_nonce() { return get_random(nonce_size()); }

      //! \pre `sodium_init()` has been called
      std::array<std::uint8_t, 32> get_key(const std::string& password) const
      {
        std::array<std::uint8_t, key_size()> key{{}};
        if (crypto_pwhash_argon2id(
          key.data(), key.size(),
          password.data(), password.size(),
          salt.data(),
          iterations, memory, pwhash_algorithm()) != 0)
        {
          throw std::runtime_error{std::string{pwhasher_name()} + " failed"};
        }
        return key;
      }

      static encrypted_file
        make(const epee::byte_slice& upayload, const std::uint64_t iterations, const std::string& password)
      {
        if (sodium_init() < 0)
          throw std::runtime_error{"Failed to initialize libsodium"};

        if (max_size() < upayload.size())
          throw std::runtime_error{std::string{"Exceeded max size for "} + cipher_name()};
        if (tag_size() < std::numeric_limits<std::size_t>::max() - upayload.size())
          throw std::runtime_error{"Exceeded max size_t after authentication tag"};

        encrypted_file out{
          cipher_name(),
          pwhasher_name(),
          get_salt(),
          get_nonce(),
          nullptr,
          std::max(iterations, ops_min()),
          memory_limit() 
        };

        const auto key = out.get_key(password);

        epee::byte_stream buffer;
        buffer.put_n(0, upayload.size() + tag_size());

        unsigned long long out_bytes = buffer.size();
        if (crypto_aead_chacha20poly1305_ietf_encrypt(
          buffer.data(), std::addressof(out_bytes),
          upayload.data(), upayload.size(),
          nullptr, 0,
          nullptr,
          out.nonce.data(), key.data()) != 0)
        {
          throw std::runtime_error{std::string{cipher_name()} + " encryption failed"};
        }

        out.epayload = epee::byte_slice{std::move(buffer)}.take_slice(out_bytes);
        return out;
      }

      //! \return Unencrypted payload, or `nullptr`.
      epee::byte_slice get_payload(const std::string& password) const
      {
        if (nonce.size() != nonce_size())
          return nullptr;
        if (salt.size() != salt_size())
          return nullptr;
        if (cipher != cipher_name())
          return nullptr;
        if (pwhasher != pwhasher_name())
          return nullptr;
        if (max_size() < epayload.size())
          return nullptr;

        if (sodium_init() < 0)
          throw std::runtime_error{"Failed to initialize libsodium"};

        const auto key = get_key(password);
                
        epee::byte_stream buffer;
        buffer.put_n(0, epayload.size());

        static_assert(
          std::numeric_limits<std::size_t>::max() <= std::numeric_limits<unsigned long long>::max()
        );
        unsigned long long out_bytes = buffer.size();
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
          buffer.data(), std::addressof(out_bytes),
          nullptr,
          epayload.data(), epayload.size(),
          nullptr, 0,
          nonce.data(), key.data()) == 0)
        {
          throw std::runtime_error{std::string{cipher_name()} + " decryption failed"};
        }

        return epee::byte_slice{std::move(buffer)}.take_slice(out_bytes);
      }
    };

    template<typename F, typename T>
    void map_encrypted_file(F& format, T& self)
    {
      wire::object(format,
        WIRE_FIELD(cipher),
        WIRE_FIELD(pwhasher),
        WIRE_FIELD(salt),
        WIRE_FIELD(nonce),
        WIRE_FIELD(epayload),
        WIRE_FIELD(iterations),
        WIRE_FIELD(memory)
      );
    }

    WIRE_DEFINE_OBJECT(encrypted_file, map_encrypted_file);

    epee::byte_slice try_load(const std::string& filename)
    {
      std::ifstream file{filename, std::ios::binary | std::ios::ate};
      if (!file.is_open())
        return nullptr;

      const auto size = file.tellg();
      if (size < 0)
        return nullptr;

      epee::byte_stream buffer;
      buffer.put_n(0, std::size_t(size));

      file.seekg(0);
      file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

      if (file.good())
        return epee::byte_slice{std::move(buffer)};
      return nullptr;
    }

#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))           
    bool atomic_file_write(const std::filesystem::path& filename, const std::filesystem::path& directory, epee::byte_slice contents) noexcept
    {
      const int fd =
        open(filename.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
      if (fd < 0)
        return false;

      bool rc = false;
      if (0 <= write(fd, contents.data(), contents.size()) && 0 <= fsync(fd))
      {
        const int dir = open(directory.c_str(), O_RDONLY);
        if (0 <= dir)
        {
          if (0 <= fsync(dir))
            rc = true;
          close(dir);
        }
      }

      close(fd);
      return rc;
    }
#else
   #error atomic_file_write not implemented for this platform
#endif
  } // anonymous

  void wallet::set_error(const std::error_code status)
  {
    const boost::lock_guard<boost::mutex> lock{sync_};
    status_ = status;
    exception_error_.clear();
  }

  void wallet::set_critical(const std::exception& e)
  {
    const boost::lock_guard<boost::mutex> lock{sync_};
    exception_error_ = e.what();
    status_.clear();
  }

  wallet::wallet(create_tag, NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds, std::shared_ptr<backend::wallet> data)
    : data_(std::move(data)),
      filename_(std::move(filename)),
      password_(std::move(password)),
      exception_error_(),
      status_(),
      thread_(),
      iterations_(kdf_rounds),
      sync_()
  {
    if (!data_)
      throw std::logic_error{"Unexpected nullptr in internal::wallet"};
    if (sodium_init() < 0)
      throw std::runtime_error{"Failed to initialize libsodium"};

    // use libsodium random, more portable
    crypto::secret_key recovery;
    randombytes_buf(std::addressof(unwrap(unwrap(recovery))), sizeof(recovery));
    
    cryptonote::account_base base{};
    base.generate(recovery, true);

    const auto& keys = base.get_keys();
   
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    data_->primary.view.sec = keys.m_view_secret_key;
    data_->primary.view.pub = keys.m_account_address.m_view_public_key;

    data_->primary.spend.sec = keys.m_spend_secret_key;
    data_->primary.spend.pub = keys.m_account_address.m_spend_public_key;

    data_->primary.generated_locally = true;
    data_->primary.type = nettype;

    store("");
  }

  wallet::wallet(open_tag, NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds, std::shared_ptr<backend::wallet> data)
    : data_(std::move(data)),
      filename_(std::move(filename)),
      password_(std::move(password)),
      exception_error_(),
      status_(),
      thread_(),
      iterations_(kdf_rounds),
      sync_()
  {
    if (!data_)
      throw std::logic_error{"Unexpected nullptr in internal::wallet"};

    try
    {
      epee::byte_slice file = try_load(filename + ".new");
      if (file.empty())
        file = try_load(filename);

      if (!file.empty())
      {
        encrypted_file contents{};
        if (!(status_ = wire::msgpack::from_bytes(std::move(file), contents)))
        {
          epee::byte_slice payload = contents.get_payload(password_);
          if (!payload.empty())
            status_ = data_->from_bytes(std::move(payload));
          else
            status_ = error::crypto_failure;
        }
      }
      else
        status_ = error::read_failure;
    }
    catch (const std::system_error& e)
    {
      status_ = e.code();
    }
    catch (const std::exception& e)
    {
      status_.clear();
      exception_error_ = e.what();
    }
  }

  wallet::~wallet()
  {}

  int wallet::status() const
  {
    int out = 0;
    std::string unused;
    statusWithErrorString(out, unused);
    return out;
  }

  std::string wallet::errorString() const
  {
    int unused = 0;
    std::string out;
    statusWithErrorString(unused, out);
    return out;
  }

  void wallet::statusWithErrorString(int& status, std::string& errorString) const
  {
    const boost::lock_guard<boost::mutex> lock{sync_};
    if (!exception_error_.empty())
    {
      status = Status_Critical;
      errorString = exception_error_;
    }
    else if (status_)
    {
      status = Status_Error;
      errorString = status_.message();
    }
    else
    {
      status = Status_Ok;
      errorString.clear();
    }
  }
  
  bool wallet::setPassword(const std::string &password)
  {
    password_ = password;
    return true;
  }

  NetworkType wallet::nettype() const { return data_->primary.type; }

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
    const std::string& real_path = path.empty() ? filename_ : path;

    std::error_code status{};
    try
    {
      expect<epee::byte_slice> payload = data_->to_bytes();
      if (payload)
      {
        const auto contents = encrypted_file::make(*payload, iterations_, password_);
        const auto payload_size = payload->size();
        *payload = nullptr; // free up some memory that is no longer needed

        epee::byte_stream buffer;
        buffer.reserve(payload_size + 2048);

        if (!(status = wire::msgpack::to_bytes(buffer, contents)))
        {
          const std::filesystem::path file = real_path;
          const std::filesystem::path new_file = real_path + ".new";
          const std::filesystem::path directory =
            std::filesystem::path{real_path}.remove_filename();

          if (std::filesystem::exists(new_file, status))
            std::filesystem::remove(file, status);
          std::filesystem::rename(new_file, file, status);
        
          // blocks until file and directory contents are synced
          if (atomic_file_write(new_file, directory, epee::byte_slice{std::move(buffer)}))
          {
            std::filesystem::remove(file, status);
            std::filesystem::rename(new_file, file, status);
          }
          else
            status = error::write_failure;
        }
      }
      else
        status = payload.error(); 
    }
    catch (const std::system_error& e)
    {
      status = e.code();
    }
    catch (const std::exception& e)
    {
      set_critical(e);
    }

    // this will clear any existing errors
    set_error(status); 
  }

  bool wallet::init(const std::string &daemon_address, uint64_t, const std::string &daemon_username, const std::string &daemon_password, bool use_ssl, bool light_wallet, const std::string &proxy_address)
  {
    if (!light_wallet)
      throw std::logic_error{"Only light_wallets are supported with this instance"};

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
      ConnectionStatus_Connected : ConnectionStatus_Disconnected;
  }

  bool wallet::setProxy(const std::string &address)
  {
    auto endpoint = net::get_tcp_endpoint(address);
    if (!endpoint)
    {
      data_->client.set_connector(null_connector{});
      set_error(endpoint.error());
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

  uint64_t wallet::estimateTransactionFee(const std::vector<std::pair<std::string, uint64_t>> &destinations,
                                            PendingTransaction::Priority priority) const
  {
    throw std::runtime_error{"Not Implemented yet"};
  }

  std::shared_ptr<TransactionHistory> wallet::history()
  {
    return std::make_shared<transaction_history>(data_);
  }


  void wallet::setListener(std::shared_ptr<WalletListener> listener)
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    data_->listener = std::move(listener);
  }
}} // lwsf // internal
