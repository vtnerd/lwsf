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
#include <string_view>
#include "address_book.h"
#include "backend.h"
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "error.h"
#include "hex.h" // monero/contrib/epee/include
#include "lwsf_config.h"
#include "mnemonics/electrum-words.h" // monero/src
#include "net/net_parse_helpers.h" // monero/contrib/epee/include
#include "net/parse.h"         // monero/src
#include "net/socks.h"         // monero/src
#include "net/socks_connect.h" // monero/src
#include "subaddress_account.h"
#include "subaddress_minor.h"
#include "transaction_history.h"
#include "wire.h"
#include "wire/msgpack.h"

namespace lwsf { namespace internal
{
  
  namespace
  {
    //! The stored wallet file always has this at beginning
    static constexpr std::string_view file_magic{"lwsf-wallet-1.0"};

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
        if (std::numeric_limits<std::size_t>::max() - upayload.size() < tag_size())
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
        static_assert(key_size() == key.size());
                
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
          nonce.data(), key.data()) != 0)
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
      std::ifstream file{filename, std::ios::binary};
      if (!file.is_open())
        return nullptr;

      {
        std::string magic;
        magic.resize(file_magic.size());
        file.read(magic.data(), magic.size());
        if (!file.good() || magic != file_magic)
          return nullptr;
      }

      file.seekg(0, std::ios::end);
      const auto size = file.tellg();
      if (size < 0 || std::size_t(size) < file_magic.size())
        return nullptr;

      epee::byte_stream buffer;
      buffer.put_n(0, std::size_t(size) - file_magic.size());

      file.seekg(file_magic.size());
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
        const char* cwd = directory.c_str();
        if (strcmp(cwd, "") == 0)
          cwd = ".";
        const int dir = open(cwd, O_RDONLY);
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

    struct unknown_exception : std::exception
    {
      unknown_exception() noexcept
        : std::exception()
      {}

      const char* what() const noexcept override { return "unknown error"; }
    };

    constexpr boost::chrono::nanoseconds to_boost(const std::chrono::nanoseconds source) noexcept
    {
      static_assert(
        std::is_same<boost::chrono::nanoseconds::rep, std::chrono::nanoseconds::rep>{}
      );
      return boost::chrono::nanoseconds{source.count()};
    }

    void load_wallet(backend::account& self, const crypto::secret_key& from, const Monero::NetworkType nettype, const bool generated_locally)
    {
      cryptonote::account_base base{};
      base.generate(from, true);

      const auto& keys = base.get_keys();

      self.view.sec = keys.m_view_secret_key;
      self.view.pub = keys.m_account_address.m_view_public_key;

      self.spend.sec = keys.m_spend_secret_key;
      self.spend.pub = keys.m_account_address.m_spend_public_key;

      self.generated_locally = generated_locally;
      self.type = nettype;
    }
  } // anonymous

  bool wallet::set_error(const std::error_code status) const
  {
    const boost::lock_guard<boost::mutex> lock{error_sync_};
    status_ = status;
    exception_error_.clear();
    return !status_;
  }

  void wallet::set_critical(const std::exception& e) const
  {
    const boost::lock_guard<boost::mutex> lock{error_sync_};
    exception_error_ = e.what();
    status_.clear();
  }

  void wallet::stop_refresh_loop()
  {
    const boost::lock_guard<boost::mutex> lock{thread_sync_};
    {
      const boost::lock_guard<boost::mutex> lock2{refresh_sync_};
      thread_state_ = state::stop;
    }
    refresh_notify_.notify_all();
    if (thread_.joinable())
      thread_.join();
  }

  void wallet::refresh_loop()
  {
    struct set_stop_
    {
      void operator()(state* val) const noexcept 
      {
         if (val)
          *val = state::stop;
      }
    };
    try
    {
      boost::unique_lock<boost::mutex> lock{refresh_sync_};
      const std::unique_ptr<state, set_stop_> set_stop{std::addressof(thread_state_)};
      while (mandatory_refresh_ || thread_state_ != state::stop)
      {
        const bool mandatory_refresh = mandatory_refresh_;
        mandatory_refresh_ = false;

        if (thread_state_ == state::run || mandatory_refresh)
        {
          // refresh has strong exception guarantee - never in partial state.
          lock.unlock();
          set_error(data_->refresh(mandatory_refresh));
          lock.lock();
        }
        else if (thread_state_ == state::skip_once)
          thread_state_ = state::run;

        // check while holding lock and before a wait call
        if (thread_state_ == state::stop)
          return;

        refresh_notify_.wait_for(lock, to_boost(config::refresh_interval));
      }
    }
    catch (const std::exception& e)
    {
      set_critical(e);
    }
    catch (...) 
    {
      set_critical(unknown_exception{});
    }
  }

  bool wallet::is_wallet_file(const std::string& path)
  {
    return !try_load(path).empty();
  }

  bool wallet::verify_password(std::string path, const std::string& password)
  {
    // We don't use a separate keys file, remove the suffix is present
    static constexpr const std::string_view keys_suffix{".keys"};
    if (keys_suffix.size() <= path.size() && std::string_view{path.data() + path.size() - keys_suffix.size()} == keys_suffix)
      path.erase(path.size() - keys_suffix.size());

    epee::byte_slice file = try_load(path);
    if (file.empty())
      return false;

    encrypted_file contents{};
    if (!wire::msgpack::from_bytes(std::move(file), contents))
      return false;
    return !contents.get_payload(password).empty();
  }

  std::vector<std::string> wallet::find(const std::string& path)
  {
    std::vector<std::string> out;
    std::filesystem::path work_dir(path);
    if(!std::filesystem::is_directory(path))
        return out;
 
    std::filesystem::recursive_directory_iterator end_itr;
    for (std::filesystem::recursive_directory_iterator itr(path); itr != end_itr; ++itr)
    {
      if (std::filesystem::is_regular_file(itr->status()))
      {
        std::string filename = itr->path().filename().string();
        if (!try_load(filename).empty())
          out.push_back(std::move(filename));
      }
    }
    return out;
  }

  wallet::wallet(create, Monero::NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds)
    : data_(std::make_shared<backend::wallet>()),
      addressbook_(),
      history_(),
      subaddresses_(),
      subaddress_minor_(), 
      filename_(std::move(filename)),
      password_(std::move(password)),
      exception_error_(),
      status_(),
      thread_(),
      iterations_(kdf_rounds),
      mixin_(config::mixin_default),
      refresh_interval_(config::refresh_interval),
      refresh_notify_(),
      error_sync_(),
      refresh_sync_(),
      thread_sync_(),
      thread_state_(state::stop),
      mandatory_refresh_(false)
  {
    if (sodium_init() < 0)
      throw std::runtime_error{"Failed to initialize libsodium"};

    // use libsodium random, more portable
    crypto::secret_key recovery;
    randombytes_buf(std::addressof(unwrap(unwrap(recovery))), sizeof(recovery));

    load_wallet(data_->primary, recovery, nettype, true); 
  }

  wallet::wallet(open, Monero::NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds)
    : data_(std::make_shared<backend::wallet>()),
      addressbook_(),
      history_(),
      subaddresses_(),
      subaddress_minor_(),
      filename_(std::move(filename)),
      password_(std::move(password)),
      exception_error_(),
      status_(),
      thread_(),
      iterations_(kdf_rounds),
      mixin_(config::mixin_default),
      refresh_interval_(config::refresh_interval),
      refresh_notify_(),
      error_sync_(),
      refresh_sync_(),
      thread_sync_(),
      thread_state_(state::stop),
      mandatory_refresh_(false)
  {
    if (!data_)
      throw std::invalid_argument{"lwsf::backend::wallet cannot be null"};

    try
    {
      epee::byte_slice file = try_load(filename_ + ".new");
      if (file.empty())
        file = try_load(filename_);

      if (!file.empty())
      {
        encrypted_file contents{};
        if (!(status_ = wire::msgpack::from_bytes(std::move(file), contents)))
        {
          epee::byte_slice payload = contents.get_payload(password_);
          if (!payload.empty())
          {
            if (!(status_ = data_->from_bytes(std::move(payload))))
            {
              // lock not needed; data_ was created and unique to us
              if (nettype != data_->primary.type)
                throw std::runtime_error{"Wallet file NetworkType does not match requested"};                
            }
          }
          else
            status_ = error::unsupported_format;
        }
      }
      else
        status_ = error::read_failure;
    }
    catch (const std::exception& e)
    {
      status_.clear();
      exception_error_ = e.what();
    }
  }

  wallet::wallet(from_mnemonic, const Monero::NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds, const std::string& mnemonic, const std::string& seed_offset)
    : data_(std::make_shared<backend::wallet>()),
      addressbook_(),
      history_(),
      subaddresses_(),
      subaddress_minor_(),
      filename_(std::move(filename)),
      password_(std::move(password)),
      exception_error_(),
      status_(),
      thread_(),
      iterations_(kdf_rounds),
      mixin_(config::mixin_default),
      refresh_interval_(config::refresh_interval),
      refresh_notify_(),
      error_sync_(),
      refresh_sync_(),
      thread_sync_(),
      thread_state_(state::stop),
      mandatory_refresh_(false)
  {
    if (sodium_init() < 0)
      throw std::runtime_error{"Failed to initialize libsodium"};

    crypto::secret_key recovery;
    std::string language;
    if (!crypto::ElectrumWords::words_to_bytes(mnemonic, recovery, language))
    {
      exception_error_ = "Electrum-style word list failed verification";
      return;
    }
      
    if (!seed_offset.empty())
      recovery = cryptonote::decrypt_key(recovery, seed_offset);

    load_wallet(data_->primary, recovery, nettype, false); 
  }


  wallet::wallet(from_keys, const Monero::NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds, const std::string& address_string, const std::string& view_key, const std::string& spend_key)
    : data_(std::make_shared<backend::wallet>()),
      addressbook_(),
      history_(),
      subaddresses_(),
      subaddress_minor_(),
      filename_(std::move(filename)),
      password_(std::move(password)),
      exception_error_(),
      status_(),
      thread_(),
      iterations_(kdf_rounds),
      mixin_(config::mixin_default),
      refresh_interval_(config::refresh_interval),
      refresh_notify_(),
      error_sync_(),
      refresh_sync_(),
      thread_sync_(),
      thread_state_(state::stop),
      mandatory_refresh_(false)
  {
    if (sodium_init() < 0)
      throw std::runtime_error{"Failed to initialize libsodium"};

    data_->primary.generated_locally = false;
    data_->primary.type = nettype;

    if (!epee::from_hex::to_buffer(epee::as_mut_byte_span(unwrap(unwrap(data_->primary.view.sec))), view_key))
    {
      exception_error_ = "view_key contained invalid hex";
      return;
    }
    if (!crypto::secret_key_to_public_key(data_->primary.view.sec, data_->primary.view.pub))
    {
      exception_error_ = "view_pub could not be computed";
      return;
    }

    crypto::secret_key spend_sec;
    if (!epee::from_hex::to_buffer(epee::as_mut_byte_span(unwrap(unwrap(data_->primary.spend.sec))), spend_key))
    {
      exception_error_ = "spend_key contained invalid hex";
      return;
    }
    if (!crypto::secret_key_to_public_key(data_->primary.spend.sec, data_->primary.spend.pub))
    {
      exception_error_ = "spend_pub could not be computed";
      return;
    }
    
    if (data_->get_spend_address({0, 0}) != address_string)
      exception_error_ = "view_key, spend_key, and address_string do not match";
  }
 
  wallet::~wallet() { stop_refresh_loop(); }

  std::string wallet::seed(const std::string& seed_offset) const
  {
    std::string language;
    crypto::secret_key key;
    {
      const boost::lock_guard<boost::mutex> lock{data_->sync};
      language = data_->primary.language;
      key = data_->primary.spend.sec;
    }

    if (language.empty())
      language = "English";

    if (!seed_offset.empty())
      key = cryptonote::encrypt_key(key, seed_offset);

    epee::wipeable_string electrum_words;
    if (!crypto::ElectrumWords::bytes_to_words(key, electrum_words, language))
    {
      set_critical(std::runtime_error{"Failed to crate seed from key for " + language});
      return {};
    }
    return std::string{electrum_words.data(), electrum_words.size()};
  }

  std::string wallet::getSeedLanguage() const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    return data_->primary.language;
  }
 
  void wallet::setSeedLanguage(const std::string &arg)
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    data_->primary.language = arg;
  }

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
    const boost::lock_guard<boost::mutex> lock{error_sync_};
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

  std::string wallet::address(const std::uint32_t accountIndex, const std::uint32_t addressIndex) const
  {
    return data_->get_spend_address({accountIndex, addressIndex});
  }

  Monero::NetworkType wallet::nettype() const { return data_->primary.type; }

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

  void wallet::stop()
  {
    const boost::lock_guard<boost::mutex> lock{refresh_sync_};
    thread_state_ = state::skip_once;
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
        buffer.write(file_magic.data(), file_magic.size());

        if (!(status = wire::msgpack::to_bytes(buffer, contents)))
        {
          const std::filesystem::path file = real_path;
          const std::filesystem::path new_file = real_path + ".new";
          const std::filesystem::path directory =
            std::filesystem::path{real_path}.remove_filename();

          if (std::filesystem::exists(new_file))
            std::filesystem::rename(new_file, file, status);
 
          // blocks until file and directory contents are synced
          if (atomic_file_write(new_file, directory, epee::byte_slice{std::move(buffer)}))
            std::filesystem::rename(new_file, file, status);
          else
            status = error::write_failure;
        }
      }
      else
        status = payload.error(); 
    }
    catch (const std::exception& e)
    {
      set_critical(e);
      return false;
    }

    // this will clear any existing errors
    return set_error(status); 
  }

  bool wallet::init(const std::string &daemon_address, uint64_t, const std::string &daemon_username, const std::string &daemon_password, bool use_ssl, bool light_wallet, const std::string &proxy_address)
  {
    if (!light_wallet)
      throw std::invalid_argument{"Only light_wallets are supported with this instance"};

    // on exceptions, reset state
    struct on_throw
    {
      void operator()(wallet* self) const
      {
        if (self)
        {
          self->stop_refresh_loop();
          self->data_->client.disconnect();
        }
      }
    };

    try
    {
      std::unique_ptr<wallet, on_throw> rollback{this};
      stop_refresh_loop();
      data_->client.disconnect();

      if (!proxy_address.empty() && !setProxy(proxy_address))
        return false;

      epee::net_utils::http::url_content url{};
      if (!epee::net_utils::parse_url(daemon_address, url))
        throw std::runtime_error{"Invalid LWS URL: " + daemon_address};
      if (!url.m_uri_content.m_path.empty())
        throw std::runtime_error{"LWS URL contains path (unsupported)"};

      if (url.schema == "https")
        use_ssl = true;

      boost::optional<epee::net_utils::http::login> login;
      if (!daemon_username.empty() || !daemon_password.empty())
        login.emplace(daemon_username, daemon_password);

      epee::net_utils::ssl_options_t options{
        use_ssl ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_disabled
      };

      data_->client.set_server(std::move(url.host), std::to_string(url.port), std::move(login), std::move(options));
      if (!connectToDaemon())
        return false;

      startRefresh();
      rollback.release();
    }
    catch (const std::exception& e)
    {
      set_critical(e);
      return false;
    }

    return true;
  }

  void wallet::setRefreshFromBlockHeight(uint64_t refresh_from_block_height)
  {
    try { set_error(data_->restore_height(refresh_from_block_height)); }
    catch (const std::exception& e)
    {
      set_critical(e);
    } 
  }

  uint64_t wallet::getRefreshFromBlockHeight() const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    return data_->primary.restore_height;
  }

  bool wallet::connectToDaemon()
  {
    struct on_throw
    {
      void operator()(wallet* self) const
      {
        if (self)
          self->data_->client.disconnect();
      }
    };

    if (data_->client.is_connected())
      return true;

    std::unique_ptr<wallet, on_throw> disconnect{this};
    if (data_->client.connect(config::connect_timeout))
    {
      const std::error_code status = data_->login();
      if (!status)
        disconnect.release();
      return set_error(status);
    }
    set_error(error::connect_failure);
    return false;
  }

  Monero::Wallet::ConnectionStatus wallet::connected() const
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
      return set_error(endpoint.error());
    }
    data_->client.set_connector(net::socks::connector{std::move(*endpoint)});
    return true;
  }

  uint64_t wallet::balance(const uint32_t accountIndex) const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};

    std::uint64_t balance = 0;
    for (const auto& tx : data_->primary.txes)
    {
      for (const auto& receive : tx.second->receives)
      {
        if (receive.second.recipient.maj_i == accountIndex)
          balance += receive.second.amount;
      }

      for (const auto& spend : tx.second->spends)
      {
        if (spend.second.sender.maj_i == accountIndex)
          balance -= spend.second.amount;
      }
    }

    return balance;
  }

  uint64_t wallet::unlockedBalance(const uint32_t accountIndex) const
  { 
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    const Monero::NetworkType net_type = data_->primary.type;
    const std::uint32_t chain_height = data_->blockchain_height;

    std::uint64_t balance = 0;
    for (const auto& tx : data_->primary.txes)
    {
      const bool unlocked = tx.second->is_unlocked(chain_height, net_type);
      for (const auto& receive : tx.second->receives)
      {
        if (unlocked && receive.second.recipient.maj_i == accountIndex)
          balance += receive.second.amount;
      }

      for (const auto& spend : tx.second->spends)
      {
        if (spend.second.sender.maj_i == accountIndex)
          balance -= spend.second.amount;
      }
    }

    return balance;
  }

  uint64_t wallet::blockChainHeight() const
  {
    const boost::unique_lock<boost::mutex> lock{data_->sync};
    return data_->primary.scan_height;
  }

  uint64_t wallet::daemonBlockChainHeight() const
  {
    const boost::unique_lock<boost::mutex> lock{data_->sync};
    return data_->blockchain_height; 
  }

  uint64_t wallet::daemonBlockChainTargetHeight() const
  { return daemonBlockChainHeight(); }

  bool wallet::synchronized() const
  { 
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    return data_->blockchain_height == data_->primary.scan_height;
  }

  void wallet::startRefresh()
  {
    const boost::lock_guard<boost::mutex> lock{thread_sync_};
    {
      const boost::lock_guard<boost::mutex> lock2{refresh_sync_};
      const bool no_refresh =
        refresh_interval_ <= std::chrono::milliseconds{0};
      if (no_refresh)
      {
        thread_state_ = state::stop;
        if (!mandatory_refresh_)
          return;
      }

      const state old_state = thread_state_;
      thread_state_ = no_refresh ? state::stop : state::run;
      if (old_state == state::stop)
      {
        if (thread_.joinable())
          thread_.join();
        thread_ = boost::thread{[this] () { this->refresh_loop(); }};
      }
    }
    refresh_notify_.notify_all();
  }

  void wallet::pauseRefresh()
  {
    const boost::lock_guard<boost::mutex> lock{refresh_sync_};
    if (thread_state_ != state::stop)
      thread_state_ = state::paused;
  }

  bool wallet::refresh()
  {
    try { return set_error(data_->refresh(true)); }
    catch (const std::exception& e) { set_critical(e); }
    return false;
  }

  void wallet::refreshAsync()
  {
    {
      const boost::lock_guard<boost::mutex> lock{refresh_sync_};
      mandatory_refresh_ = true;
    }
    startRefresh();
  }

  void wallet::setAutoRefreshInterval(int millis)
  {
    using rep_type = std::chrono::milliseconds::rep;
    static_assert(std::numeric_limits<int>::max() <= std::numeric_limits<rep_type>::max());

    boost::unique_lock<boost::mutex> lock{refresh_sync_};
    refresh_interval_ = std::chrono::milliseconds{millis};
    if (millis <= 0)
    {
      thread_state_ = state::stop;
      lock.unlock();
      stop_refresh_loop();
    }
  }

  int wallet::autoRefreshInterval() const
  {
    return refresh_interval_.count();
  }

  void wallet::addSubaddressAccount(const std::string& label)
  {
    data_->add_subaccount(label);
  }

  std::size_t wallet::numSubaddressAccounts() const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    return data_->primary.subaccounts.size();
  }


  std::size_t wallet::numSubaddresses(const std::uint32_t accountIndex) const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    const auto account = data_->primary.subaccounts.find(accountIndex);
    if (account != data_->primary.subaccounts.end())
      return account->second.minor.size();
    set_critical(std::runtime_error{"numSubaddresses failed, " + std::to_string(accountIndex) + " does not exist"});
    return 0;
  }

  std::string wallet::getSubaddressLabel(const std::uint32_t accountIndex, const std::uint32_t addressIndex) const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    const auto major = data_->primary.subaccounts.find(accountIndex);
    if (major != data_->primary.subaccounts.end())
    {
      const auto minor = major->second.minor.find(addressIndex);
      if (minor != major->second.minor.end())
        return minor->second.label;
    }
    set_critical(std::runtime_error{"getSubaddressLabel failed, " + std::to_string(accountIndex) + "," + std::to_string(addressIndex) + " does not exist"});
    return {};
  }

  void wallet::setSubaddressLabel(const std::uint32_t accountIndex, const std::uint32_t addressIndex, const std::string &label)
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    auto major = data_->primary.subaccounts.find(accountIndex);
    if (major != data_->primary.subaccounts.end())
    {
      auto minor = major->second.minor.find(addressIndex);
      if (minor != major->second.minor.end())
      {
        minor->second.label = label;
        return;
      }
    }
    set_critical(std::runtime_error{"setSubaddressLabel failed, " + std::to_string(accountIndex) + "," + std::to_string(addressIndex) + " does not exist"});
  }

  void wallet::disposeTransaction(Monero::PendingTransaction * t)
  {
    delete t;
  }

  uint64_t wallet::estimateTransactionFee(const std::vector<std::pair<std::string, uint64_t>> &destinations,
                                          Monero::PendingTransaction::Priority priority) const
  {
    throw std::runtime_error{"Not Implemented yet"};
  }
  
  bool wallet::exportKeyImages(const std::string &filename, bool all)
  {
    throw std::runtime_error{"exportKeyImages not implemented"};
  }
   
  bool wallet::importKeyImages(const std::string &filename)
  {
    throw std::runtime_error{"importKeyImages not implemented"};
  }

  bool wallet::exportOutputs(const std::string &filename, bool all)
  {
    throw std::runtime_error{"exportOutputs not implemented"};
  }

  bool wallet::importOutputs(const std::string &filename)
  {
    throw std::runtime_error{"importOutputs not implemented"};
  }

  bool wallet::scanTransactions(const std::vector<std::string> &txids)
  {
    throw std::runtime_error{"scanTransactions not implemented"};
  }

  Monero::AddressBook* wallet::addressBook()
  {
    if (!addressbook_)
      addressbook_ = std::make_unique<address_book>(data_);
    return addressbook_.get();
  }

  Monero::Subaddress* wallet::subaddress()
  {
    if (!subaddress_minor_)
      subaddress_minor_ = std::make_unique<subaddress_minor>(data_);
    return subaddress_minor_.get();
  }

  Monero::TransactionHistory* wallet::history()
  {
    if (!history_)
      history_ = std::make_unique<transaction_history>(data_);
    return history_.get();
  } 

  Monero::SubaddressAccount* wallet::subaddressAccount()
  {
    if (!subaddresses_)
      subaddresses_ = std::make_unique<subaddress_account>(data_);
    return subaddresses_.get();
  }

  void wallet::setListener(Monero::WalletListener* listener)
  {
    {
      const boost::lock_guard<boost::mutex> lock{data_->sync_listener};
      data_->listener = listener;
    }
    if (listener)
      listener->onSetWallet(this);
  }

  std::uint32_t wallet::defaultMixin() const
  {
    return mixin_;
  }

  void wallet::setDefaultMixin(const std::uint32_t arg)
  {
    mixin_ = arg;
  }

  bool wallet::setCacheAttribute(const std::string &key, const std::string &val)
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    data_->primary.attributes.try_emplace(key).first->second = val;
    return true;
  }

  std::string wallet::getCacheAttribute(const std::string &key) const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    const auto attribute = data_->primary.attributes.find(key);
    if (attribute != data_->primary.attributes.end())
      return attribute->second;
    set_critical(std::runtime_error{"attribute " + key + " does not exist"});
    return {};
  }

  bool wallet::setUserNote(const std::string &txid, const std::string &note)
  {
    crypto::hash binary_id{};
    if (!epee::string_tools::hex_to_pod(txid, binary_id))
      return false;

    const boost::lock_guard<boost::mutex> lock{data_->sync};
    auto iter = data_->primary.txes.find(binary_id);
    if (iter == data_->primary.txes.end())
      return false;

    iter->second->description = note;
    return true;
  }

  std::string wallet::getUserNote(const std::string &txid) const
  {
    crypto::hash binary_id{};
    if (!epee::string_tools::hex_to_pod(txid, binary_id))
    {
      set_critical(std::runtime_error{"getUserNote given invalid hex id"});
      return {};
    }

    const boost::lock_guard<boost::mutex> lock{data_->sync};
    auto iter = data_->primary.txes.find(binary_id);
    if (iter == data_->primary.txes.end())
      return {};
    return iter->second->description;
  }

  std::string wallet::getTxKey(const std::string &txid) const
  {
    crypto::hash binary_id{};
    if (!epee::string_tools::hex_to_pod(txid, binary_id))
    {
      set_critical(std::runtime_error{"getTxKey given invalid hex id"});
      return {};
    }

    const boost::lock_guard<boost::mutex> lock{data_->sync};
    auto iter = data_->primary.txes.find(binary_id);
    if (iter == data_->primary.txes.end())
    {
      set_critical(std::runtime_error{"getTxKey tx not found"});
      return {};
    }

    static constexpr const auto hex_size = sizeof(crypto::secret_key) * 2;

    std::string out;
    out.reserve(iter->second->spends.size() * hex_size);

    for (const auto& spend : iter->second->spends)
    {
      if (spend.second.secret)
      {
        out.insert(out.end(), hex_size, 0);
        if (!epee::to_hex::buffer({out.data() + out.size() - hex_size, hex_size}, epee::as_byte_span(unwrap(unwrap(*spend.second.secret)))))
        {
          set_critical(std::runtime_error{"getTxKey conversion to hex failure"});
          return {};
        }
      }
    }

    return out;
  }
}} // lwsf // internal
