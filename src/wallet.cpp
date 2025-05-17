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
#include "cryptonote_core/cryptonote_tx_utils.h"      // monero/src
#include "error.h"
#include "hex.h" // monero/contrib/epee/include
#include "lwsf_config.h"
#include "mnemonics/electrum-words.h" // monero/src
#include "net/net_parse_helpers.h" // monero/contrib/epee/include
#include "net/parse.h"         // monero/src
#include "net/socks.h"         // monero/src
#include "net/socks_connect.h" // monero/src
#include "pending_transaction.h"
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
        return boost::make_exceptional_future<boost::asio::ip::tcp::socket>(
          std::runtime_error{"invalid proxy value"}
        );
      }
    };

    std::uint64_t calculate_fee_from_weight(const std::uint64_t base_fee, const std::uint64_t weight, const std::uint64_t fee_quantization_mask)
    {
      uint64_t fee = weight * base_fee;
      fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
      return fee;
    }

    std::size_t estimate_rct_tx_size(const std::size_t n_inputs, const std::size_t n_outputs, const std::uint32_t mixin, const std::size_t extra_size)
    {
      std::size_t size = 0;

      // tx prefix

      // first few bytes
      size += 1 + 6;

      // vin
      size += n_inputs * (1+6+(mixin+1)*2+32);

      // vout
      size += n_outputs * (6+32);

      // extra
      size += extra_size;

      // rct signatures

      // type
      size += 1;

      // rangeSigs
      //if (bulletproof || bulletproof_plus)
      {
        std::size_t log_padded_outputs = 0;
        while ((1<<log_padded_outputs) < n_outputs)
          ++log_padded_outputs;
        size += (2 * (6 + log_padded_outputs) + /*(bulletproof_plus ? */ 6 /* : (4 + 5))*/) * 32 + 3;
      }
      //else
      //  size += (2*64*32+32+64*32) * n_outputs;

      // MGs/CLSAGs
      //if (clsag)
        size += n_inputs * (32 * (mixin+1) + 64);
      //else
      //  size += n_inputs * (64 * (mixin+1) + 32);

      //if (use_view_tags)
        size += n_outputs * sizeof(crypto::view_tag);

      // mixRing - not serialized, can be reconstructed
      /* size += 2 * 32 * (mixin+1) * n_inputs; */

      // pseudoOuts
      size += 32 * n_inputs;
      // ecdhInfo
      size += 8 * n_outputs;
      // outPk - only commitment is saved
      size += 32 * n_outputs;
      // txnFee
      size += 4;

      return size;
    }

    std::uint64_t estimate_tx_weight(const std::size_t n_inputs, const std::size_t n_outputs, const std::uint32_t mixin, const std::size_t extra_size)
    {
      size_t size = estimate_rct_tx_size(n_inputs, n_outputs, mixin, extra_size);
      if (/*use_rct && (bulletproof || bulletproof_plus) && */n_outputs > 2)
      {
        const uint64_t bp_base = (32 * (/*(bulletproof_plus ?*/ 6 /* : 9)*/ + 7 * 2)) / 2; // notional size of a 2 output proof, normalized to 1 proof (ie, divided by 2)
        size_t log_padded_outputs = 2;
        while ((1<<log_padded_outputs) < n_outputs)
          ++log_padded_outputs;
        uint64_t nlr = 2 * (6 + log_padded_outputs);
        const uint64_t bp_size = 32 * (/*(bulletproof_plus ? */ 6 /* : 9)*/ + nlr);
        const uint64_t bp_clawback = (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
        MDEBUG("clawback on size " << size << ": " << bp_clawback);
        size += bp_clawback;
      }
      return size;
    }

    std::uint64_t estimate_fee(const std::uint64_t base_fee, const std::size_t n_inputs, const std::size_t n_outputs, const std::uint32_t mixin, const std::size_t extra_size, const std::uint64_t fee_mask)
    {
      return calculate_fee_from_weight(base_fee, estimate_tx_weight(n_inputs, n_outputs, mixin, extra_size), fee_mask);
    }

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

    void init_wallet(backend::wallet& self, const crypto::secret_key& from, const Monero::NetworkType nettype, const bool generated_locally)
    {
      cryptonote::account_base base{};
      base.generate(from, true);

      const auto& keys = base.get_keys();

      self.primary.view.sec = keys.m_view_secret_key;
      self.primary.view.pub = keys.m_account_address.m_view_public_key;

      self.primary.spend.sec = keys.m_spend_secret_key;
      self.primary.spend.pub = keys.m_account_address.m_spend_public_key;

      self.primary.generated_locally = generated_locally;
      self.primary.type = nettype;

      self.primary.address = self.get_spend_address({0, 0});
    }
  } // anonymous

  bool wallet::set_error(const std::error_code error, const bool clear) const
  {
    if (clear || error)
    {
      const boost::lock_guard<boost::mutex> lock{error_sync_};
      error_ = error;
    }
    return !error;
  }

  void wallet::set_critical(const std::exception& e) const
  {
    const boost::lock_guard<boost::mutex> lock{error_sync_};
    exception_error_ = e.what();
  }

  template<typename F>
  void wallet::queue_work(F&& f)
  {
    {
      const boost::lock_guard<boost::mutex> lock{refresh_sync_};
      work_queue_.push_back(std::forward<F>(f));
    }
    startRefresh();
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
      std::chrono::steady_clock::time_point last_refresh;
      boost::unique_lock<boost::mutex> lock{refresh_sync_};
      const std::unique_ptr<state, set_stop_> set_stop{std::addressof(thread_state_)};
      while (mandatory_refresh_ || thread_state_ != state::stop || !work_queue_.empty())
      {
        while (!work_queue_.empty())
        {
          const std::function<std::error_code()> work{std::move(work_queue_.front())};
          work_queue_.pop_front();
          lock.unlock();
          if (work)
            set_error(work());
          lock.lock();
        }

        const bool mandatory_refresh = mandatory_refresh_;
        mandatory_refresh_ = false;

        const auto now = std::chrono::steady_clock::now();
        if (mandatory_refresh_ || (refresh_interval_ <= now - last_refresh && thread_state_ == state::run))
        {
          // refresh has strong exception guarantee - never in partial state.
          lock.unlock();
          last_refresh = now;
          set_error(data_->refresh(mandatory_refresh), true /*clear*/);
          lock.lock();
        }
        else if (thread_state_ == state::skip_once)
          thread_state_ = state::run;

        // check while holding lock and before a wait call
        if (thread_state_ == state::stop)
          return;

        const auto last_state = thread_state_;
        refresh_notify_.wait_for(
          lock, to_boost(refresh_interval_), [this, last_state] () {
            return mandatory_refresh_ || thread_state_ != last_state || !work_queue_.empty();
        });
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
      work_queue_(),
      exception_error_(),
      error_(),
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

    init_wallet(*data_, recovery, nettype, true);
  }

  wallet::wallet(open, Monero::NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds)
    : data_(std::make_shared<backend::wallet>()),
      addressbook_(),
      history_(),
      subaddresses_(),
      subaddress_minor_(),
      filename_(std::move(filename)),
      password_(std::move(password)),
      work_queue_(),
      exception_error_(),
      error_(),
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
    try
    {
      epee::byte_slice file = try_load(filename_ + ".new");
      if (file.empty())
        file = try_load(filename_);

      if (file.empty())
        throw std::runtime_error{"Unable to open wallet file " + filename_};

      encrypted_file contents{};
      if (std::error_code error = wire::msgpack::from_bytes(std::move(file), contents))
        throw std::system_error{error};

      epee::byte_slice payload = contents.get_payload(password_);
      if (std::error_code error = data_->from_bytes(std::move(payload)))
        throw std::system_error{error};

      // lock not needed; data_ was created and unique to us
      if (nettype != data_->primary.type)
        throw std::runtime_error{"Wallet file NetworkType does not match requested"};
    }
    catch (const std::exception& e)
    {
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
      work_queue_(),
      exception_error_(),
      error_(),
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

    init_wallet(*data_, recovery, nettype, false);
  }


  wallet::wallet(from_keys, const Monero::NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds, const std::string& address_string, const std::string& view_key, const std::string& spend_key)
    : data_(std::make_shared<backend::wallet>()),
      addressbook_(),
      history_(),
      subaddresses_(),
      subaddress_minor_(),
      filename_(std::move(filename)),
      password_(std::move(password)),
      work_queue_(),
      exception_error_(),
      error_(),
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

  void wallet::add_subaddress(const std::uint32_t accountIndex, std::string label)
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    auto& accts = data_->primary.subaccounts;

    if (accts.size() <= accountIndex)
      throw std::runtime_error{"add_subaddress: account does not exist"};

    auto& acct = accts.at(accountIndex);
    if (std::numeric_limits<std::uint32_t>::max() <= acct.last)
      throw std::runtime_error{"add_subaddress: exceeded minor indexes"};

    const std::uint32_t min_i = ++acct.last;
    if (!label.empty())
      acct.detail.try_emplace(min_i).first->second.label = std::move(label);

    queue_work([=] () { return data_->register_subaddress(accountIndex, min_i); });
  }

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
    else if (error_)
    {
      status = Status_Error;
      errorString = error_.message();
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

    try
    {
      epee::byte_slice payload = data_->to_bytes().value();
      const auto contents = encrypted_file::make(payload, iterations_, password_);
      const auto payload_size = payload.size();
      payload = nullptr; // free up some memory that is no longer needed

      epee::byte_stream buffer;
      buffer.reserve(payload_size + 2048);
      buffer.write(file_magic.data(), file_magic.size());

      if (std::error_code error = wire::msgpack::to_bytes(buffer, contents))
        throw std::system_error{error};

      const std::filesystem::path file = real_path;
      const std::filesystem::path new_file = real_path + ".new";
      const std::filesystem::path directory =
        std::filesystem::path{real_path}.remove_filename();

      if (std::filesystem::exists(new_file))
        std::filesystem::rename(new_file, file);

      // blocks until file and directory contents are synced
      if (!atomic_file_write(new_file, directory, epee::byte_slice{std::move(buffer)}))
        throw std::runtime_error{"Failed to write file " + real_path};

      std::filesystem::rename(new_file, file);
    }
    catch (const std::exception& e)
    {
      set_critical(e);
      return false;
    }

    return true;
  }

  bool wallet::init(const std::string &daemon_address, uint64_t, const std::string &daemon_username, const std::string &daemon_password, bool use_ssl, bool light_wallet, const std::string &proxy_address)
  {
    if (!light_wallet)
      throw std::invalid_argument{"Only light_wallets are supported with this instance"};

    try
    {
      epee::net_utils::http::url_content url{};
      if (!epee::net_utils::parse_url(daemon_address, url))
        throw std::runtime_error{"Invalid LWS URL: " + daemon_address};
      if (!url.m_uri_content.m_path.empty())
        throw std::runtime_error{"LWS URL contains path (unsupported)"};

      if (!proxy_address.empty() && !setProxy(proxy_address))
        return false;

      boost::optional<epee::net_utils::http::login> login;
      if (!daemon_username.empty() || !daemon_password.empty())
        login.emplace(daemon_username, daemon_password);

      // verify cert if `use_ssl == true`, otherwise autodetect if `https`
      // specified.
      const bool https = url.schema == "https";
      epee::net_utils::ssl_options_t options{
        !use_ssl ?
          (https ? epee::net_utils::ssl_support_t::e_ssl_support_autodetect : epee::net_utils::ssl_support_t::e_ssl_support_disabled) :
            epee::net_utils::ssl_support_t::e_ssl_support_enabled
      };

      data_->client.set_server(std::move(url.host), std::to_string(url.port), std::move(login), std::move(options));
    }
    catch (const std::exception& e)
    {
      set_critical(e);
      return false;
    }

    return true;
  }

  void wallet::setRefreshFromBlockHeight(const std::uint64_t height)
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    data_->primary.requested_start = std::min(data_->primary.requested_start, height);
    queue_work([this, height] () { return data_->restore_height(height); });
  }

  uint64_t wallet::getRefreshFromBlockHeight() const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    return data_->primary.restore_height;
  }

  void wallet::setSubaddressLookahead(uint32_t major, uint32_t minor)
  {
    queue_work([this, major, minor] () { return data_->set_lookahead(major, minor); });
  }

  bool wallet::connectToDaemon()
  {
    const bool connected = data_->client.is_connected();
    boost::unique_lock<boost::mutex> lock{data_->sync};
    if (connected && data_->passed_login)
      return true;

    if (connected || data_->client.connect(config::connect_timeout))
    {
      lock.unlock();
      return set_error(data_->login());
    }
    return set_error(rpc::error::no_response);
  }

  Monero::Wallet::ConnectionStatus wallet::connected() const
  {
    if (!data_->client.is_connected())
      return ConnectionStatus_Disconnected;

    const boost::lock_guard<boost::mutex> lock{data_->sync};
    return data_->passed_login ?
      ConnectionStatus_Connected : ConnectionStatus_Disconnected;
  }

  bool wallet::setProxy(const std::string &address)
  {
    data_->client.disconnect();
    if (address.empty())
      data_->client.set_connector(epee::net_utils::direct_connect{});
    else
    {
      auto endpoint = net::get_tcp_endpoint(address);
      if (!endpoint)
      {
        data_->client.set_connector(null_connector{});
        return set_error(endpoint.error());
      }
      data_->client.set_connector(net::socks::connector{std::move(*endpoint)});
    }
    return true;
  }

  uint64_t wallet::balance(const uint32_t accountIndex) const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};

    std::uint64_t balance = 0;
    for (const auto& tx : data_->primary.txes)
    {
      if (tx.second->failed)
        continue;

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
      if (tx.second->failed)
        continue;

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
    state old_state = state::stop;
    {
      const boost::lock_guard<boost::mutex> lock2{refresh_sync_};
      old_state = thread_state_;
      const bool no_refresh =
        refresh_interval_ <= std::chrono::milliseconds{0};
      if (no_refresh)
      {
        thread_state_ = state::stop;
        if (!mandatory_refresh_ && work_queue_.empty())
          return;
      }
      else
        thread_state_ = state::run;
    }
    refresh_notify_.notify_all();

    if (old_state == state::stop)
    {
      if (thread_.joinable())
        thread_.join();
      thread_ = boost::thread{[this] () { this->refresh_loop(); }};
    }
  }

  void wallet::pauseRefresh()
  {
    const boost::lock_guard<boost::mutex> lock{refresh_sync_};
    if (thread_state_ != state::stop)
      thread_state_ = state::paused;
  }

  bool wallet::refresh()
  {
    try { return set_error(data_->refresh(true), true /* clear */); }
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
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    auto& accts = data_->primary.subaccounts;

    const std::size_t index = accts.size();
    if (std::numeric_limits<std::uint32_t>::max() < index)
      throw std::runtime_error{"addSubddressAccount exceeded subaddress indexes"};

    accts.emplace_back().detail.try_emplace(0).first->second.label = label;
    queue_work([this, index] () { return data_->register_subaccount(index); });
  }

  std::size_t wallet::numSubaddressAccounts() const
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    return data_->primary.subaccounts.size();
  }

  std::size_t wallet::numSubaddresses(const std::uint32_t accountIndex) const
  {
    static_assert(std::numeric_limits<std::uint32_t>::max() <= std::numeric_limits<std::size_t>::max());
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (accountIndex < data_->primary.subaccounts.size())
      return std::size_t(data_->primary.subaccounts.at(accountIndex).last) + 1;
    set_critical(std::runtime_error{"numSubaddresses failed, " + std::to_string(accountIndex) + " does not exist"});
    return 0;
  }

  std::string wallet::getSubaddressLabel(const std::uint32_t accountIndex, const std::uint32_t addressIndex) const
  {
    static_assert(std::numeric_limits<std::uint32_t>::max() <= std::numeric_limits<std::size_t>::max());
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (accountIndex < data_->primary.subaccounts.size())
      return std::string{data_->primary.subaccounts.at(accountIndex).sub_label(addressIndex)};
    set_critical(std::runtime_error{"getSubaddressLabel failed, " + std::to_string(accountIndex) + "," + std::to_string(addressIndex) + " does not exist"});
    return {};
  }

  void wallet::setSubaddressLabel(const std::uint32_t accountIndex, const std::uint32_t addressIndex, const std::string &label)
  {
    static_assert(std::numeric_limits<std::uint32_t>::max() <= std::numeric_limits<std::size_t>::max());
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (accountIndex < data_->primary.subaccounts.size())
    {
      auto& acct = data_->primary.subaccounts[accountIndex];
      if (addressIndex <= acct.last)
      {
        if (!addressIndex || !label.empty())
          acct.detail.try_emplace(addressIndex).first->second.label = label;
        else
          acct.detail.erase(addressIndex);
        return;
      }
    }
    set_critical(std::runtime_error{"setSubaddressLabel failed, " + std::to_string(accountIndex) + "," + std::to_string(addressIndex) + " does not exist"});
  }

  Monero::PendingTransaction* wallet::createTransactionMultDest(const std::vector<std::string> &dst_addr, const std::string &payment_id,
                                                   Monero::optional<std::vector<uint64_t>> amount, uint32_t mixin_count,
                                                   Monero::PendingTransaction::Priority priority,
                                                   uint32_t subaddr_account,
                                                   std::set<uint32_t> subaddr_indices)
  {
    if (!mixin_count)
      mixin_count = mixin_;

    std::unique_ptr<internal::pending_transaction> out;
    const auto tx_error = [this] (std::error_code error)
    {
      return std::make_unique<internal::pending_transaction>(data_, std::move(error));
    };

    try
    {
      /* This design is funky, but guards against exceptions in destructors
      of stack elements. Everything on the stack (except for arguments) is
      cleaned up before the uniue_ptr is released. */
      out = [&, this] ()
        {
          if (!amount && dst_addr.size() > 1)
            return tx_error(error::tx_sweep);
          if (amount && amount->size() != dst_addr.size())
            return tx_error(error::tx_size_mismatch);
          if (!payment_id.empty())
            return tx_error(error::tx_long_pid);

          cryptonote::network_type ctype{};
          Monero::NetworkType mtype{};
          std::uint64_t per_byte_fee = 0;
          std::uint64_t fee_mask = 0;
          std::string change_address;
          cryptonote::account_keys keys{};
          cryptonote::account_public_address change_account{};
          std::unordered_map<crypto::public_key, std::pair<std::pair<std::uint64_t, std::uint64_t>, std::shared_ptr<const backend::transaction>>> unspent;
          {
            data_->refresh(); // get latest outputs, block height, and fee info

            const boost::lock_guard<boost::mutex> lock{data_->sync};
            per_byte_fee = data_->per_byte_fee;
            fee_mask = data_->fee_mask;

            if (!per_byte_fee || !fee_mask || !data_->passed_login)
              return tx_error(data_->refresh_error);

            mtype = data_->primary.type;
            ctype = data_->get_net_type();
            change_address = data_->get_spend_address({subaddr_account, 0});
            keys = data_->get_primary_keys();
            change_account = data_->get_spend_account({subaddr_account, 0});
            const std::uint64_t height = data_->blockchain_height;

            if (!amount && subaddr_indices.empty())
            {
              const std::uint32_t max = data_->primary.subaccounts.at(subaddr_account).last;
              for (std::uint64_t index = 0; index <= max; ++index)
                subaddr_indices.insert(std::uint32_t(index));
            }

            for (const auto& tx : data_->primary.txes)
            {
              if (!tx.second->is_unlocked(height, mtype))
                continue; // ignore locked amounts

              for (const auto& receive : tx.second->receives)
              {
                /* Subtract by max for map below - that map will sort by amount
                then reverse global index. This will have a bias towards newer
                outputs, which is standard behavior. */
                static constexpr std::uint64_t max =
                  std::numeric_limits<std::uint64_t>::max();
                const std::uint64_t amount = receive.second.amount;
                const rpc::address_meta source = receive.second.recipient;
                if (amount && source.maj_i == subaddr_account && (subaddr_indices.empty() || subaddr_indices.count(source.min_i)))
                  unspent.try_emplace(receive.first).first->second = {{amount, max - receive.second.global_index}, tx.second};
              }
            }

            for (const auto& tx : data_->primary.txes)
            {
              for (const auto& spend : tx.second->spends)
                unspent.erase(spend.second.output_pub);
            }
          }

          // actually sorted by amount then reverse index (see comment above)
          std::map<std::pair<std::uint64_t, std::uint64_t>, std::pair<crypto::public_key, std::shared_ptr<const backend::transaction>>> unspent_by_amount_then_index;
          for (const auto& tx : unspent)
            unspent_by_amount_then_index.try_emplace(tx.second.first).first->second = {tx.first, tx.second.second};
          unspent.clear(); // free up some memory

          const bool subtract_from_dest = !amount;
          if (subtract_from_dest)
          {
            std::uint64_t total_unspent = 0;
            for (const auto& tx : unspent)
            {
              const auto output = tx.second.second->receives.find(tx.first);
              if (output == tx.second.second->receives.end())
                throw std::logic_error{"Expected output pub"};
              total_unspent += output->second.amount;
            }
            amount = std::vector<std::uint64_t>{total_unspent};
          }

          if (amount->size() < dst_addr.size())
            throw std::logic_error{"Sanity check failed: address vec <= amount vec"};

          std::string extra_nonce;
          std::vector<cryptonote::tx_destination_entry> dests;
          std::multiset<std::pair<std::uint64_t, std::string>> transfers;
          for (std::size_t i = 0; i < dst_addr.size(); ++i)
          {
            cryptonote::address_parse_info info{};
            if (!cryptonote::get_account_address_from_str(info, ctype, dst_addr.at(i)))
              return tx_error(error::tx_invalid_address);

            if (info.has_payment_id)
            {
              if (!extra_nonce.empty())
                return tx_error(error::tx_two_pid);
              cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, info.payment_id);
            }

            transfers.insert({amount->at(i), dst_addr.at(i)});

            auto& dest = dests.emplace_back();
            dest.original = dst_addr.at(i);
            dest.addr = info.address;
            dest.amount = amount->at(i);
            dest.is_subaddress = info.is_subaddress;
            dest.is_integrated = info.has_payment_id;
          }

          for (std::size_t i = dst_addr.size(); i < amount->size(); ++i)
          {
            auto& dest = dests.emplace_back();
            dest.original = change_address;
            dest.addr = change_account;
            dest.amount = amount->at(i);
            dest.is_subaddress = subaddr_account;
            dest.is_integrated = false;
          }

          std::vector<std::uint8_t> extra;
          if (!extra_nonce.empty() && !cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce))
            return tx_error(error::tx_extra);

          std::vector<std::pair<crypto::public_key, std::shared_ptr<const backend::transaction>>> spending;
          {
            std::uint64_t fee = 0;
            std::uint64_t remaining =
              std::accumulate(amount->begin(), amount->end(), std::uint64_t(0));

            while (bool(remaining + fee))
            {
              if (unspent_by_amount_then_index.empty())
              {
                if (subtract_from_dest && !remaining)
                  break;
                return tx_error(error::tx_low_funds);
              }

              /* Check if we can omit change address for more efficiency. We
                must have at least 2 outputs for uniformity/privacy. */
              if (1 < dests.size())
              {
                fee = estimate_fee(per_byte_fee, spending.size() + 1, dests.size(), mixin_count, extra.size(), fee_mask);
                const std::uint64_t needed = remaining + fee;
                const auto output = unspent_by_amount_then_index.lower_bound({needed, 0});
                if (output != unspent_by_amount_then_index.end() && needed == output->first.first)
                {
                  remaining = 0;
                  break;
                }
              }

              // check
              fee = estimate_fee(per_byte_fee, spending.size() + 1, dests.size() + 1, mixin_count, extra.size(), fee_mask);

              const std::uint64_t needed = remaining + fee;
              auto output = unspent_by_amount_then_index.lower_bound({needed, 0});
              if (output == unspent_by_amount_then_index.end())
                --output;

              const std::uint64_t this_amount = output->first.first;
              const bool complete = needed <= this_amount;
              spending.emplace_back(output->second.first, output->second.second);
              unspent_by_amount_then_index.erase(output);

              remaining -= this_amount;
              if (complete)
                break;
            }

            if (subtract_from_dest)
            {
              if (dests.size() != 1)
                throw std::logic_error{"Sanity check: subtract_from_dest && dest.size() == 1"};
              if (dests.back().amount < fee)
                return tx_error(error::tx_low_funds);
              dests.back().amount -= fee;
              fee = 0;
            }

            const std::uint64_t change = (std::uint64_t(0) - remaining) - fee;
            if (change || dests.size() == 1)
            {
              auto& change_dest = dests.emplace_back();
              change_dest.original = change_address;
              change_dest.addr = change_account;
              change_dest.amount = change;
              change_dest.is_subaddress = bool(subaddr_account);
              change_dest.is_integrated = false;
            }

            if (dests.size() < config::minimum_outputs)
              throw std::logic_error{"Sanity check: config::minium_outputs <= dests.size()"};

            remaining = 0;
            for (const auto& source : spending)
            {
              const auto output = source.second->receives.find(source.first);
              if (output == source.second->receives.end())
                throw std::logic_error{"Failed sanity check: source output does not exist"};
              remaining += output->second.amount;
            }

            for (const auto& dest : dests)
              remaining -= dest.amount;

            if (fee != remaining)
              throw std::logic_error{"Sanity check: inputs.amounts == outputs.amounts + fee"};
          }
          unspent_by_amount_then_index.clear(); // free some memory

          const auto rct_amount = [] (const backend::transfer_in& source)
          {
            return source.rct_mask ? 0 : source.amount;
          };

          std::vector<rpc::random_outputs> decoys;
          {
            rpc::get_random_outs_request req{};
            req.count = mixin_count;
            for (const auto& spend : spending)
              req.amounts.push_back(rpc::uint64_string(rct_amount(spend.second->receives.at(spend.first))));

            auto resp = data_->get_decoys(req);
            if (!resp)
              return tx_error(resp.error());
            decoys = std::move(*resp);
          }

          struct by_amount
          {
            bool operator()(const rpc::random_outputs& lhs, const rpc::random_outputs& rhs) const noexcept
            {
              return lhs.amount < rhs.amount;
            }
            bool operator()(const rpc::random_outputs& lhs, const std::uint64_t rhs) const noexcept
            {
              return lhs.amount < rpc::uint64_string(rhs);
            }
          };
          std::sort(decoys.begin(), decoys.end(), by_amount{});

          std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subs;
          std::vector<cryptonote::tx_source_entry> sources;
          for (const auto& spend : spending)
          {
            const auto& source = spend.second->receives.at(spend.first);
            {
              const boost::lock_guard<boost::mutex> lock{data_->sync};
              subs.insert({data_->get_spend_public(source.recipient), {source.recipient.maj_i, source.recipient.min_i}});
            }

            auto& entry = sources.emplace_back();
            if (source.rct_mask)
              entry.outputs.emplace_back(source.global_index, rct::ctkey{rct::pk2rct(spend.first), rct::commit(source.amount, *source.rct_mask)});
            else
              entry.push_output(source.global_index, spend.first, source.amount);

            {
              const std::uint64_t amount = rct_amount(source);
              const auto ring = std::lower_bound(decoys.begin(), decoys.end(), amount, by_amount{});
              if (ring == decoys.end() || ring->amount != rpc::uint64_string(amount))
                return tx_error(error::tx_decoys);

              for (const auto& decoy : ring->outputs)
                entry.outputs.emplace_back(std::uint64_t(decoy.global_index), rct::ctkey{decoy.public_key, decoy.rct});

              decoys.erase(ring);
            }

            entry.real_output_in_tx_index = source.index;
            entry.real_out_tx_key = source.tx_pub;
            entry.amount = source.amount;
            entry.rct = bool(source.rct_mask);
            if (entry.rct)
              entry.mask = *source.rct_mask;
          }

          const auto ring_sort = [] (const auto& lhs, const auto& rhs)
          {
            return lhs.first < rhs.first;
          };
          const auto ring_compare = [] (const auto& lhs, const auto& rhs)
          {
            return lhs.first == rhs.first;
          };

          std::shuffle(sources.begin(), sources.end(), crypto::random_device{});
          std::shuffle(dests.begin(), dests.end(), crypto::random_device{}); 
          for (auto& source : sources)
          {
            if (source.outputs.empty())
              throw std::runtime_error{"Sanity check: ring is !empty"};

            const std::uint64_t real_source = source.outputs.front().first;
            std::sort(source.outputs.begin(), source.outputs.end(), ring_sort);
            if (std::unique(source.outputs.begin(), source.outputs.end(), ring_compare) != source.outputs.end())
              throw std::logic_error{"Sanity check: each ring destination is unique"};

            for (std::size_t i = 0; i < source.outputs.size(); ++i)
            {
              if (source.outputs.at(i).first == real_source)
              {
                source.real_output = i;
                break;
              }
            }
          }

          static constexpr const rct::RCTConfig config{
            rct::RangeProofPaddedBulletproof, config::bulletproof_version
          };

          crypto::secret_key tx_key;
          std::vector<crypto::secret_key> tx_keys;
          cryptonote::transaction tx;
          if (!cryptonote::construct_tx_and_get_tx_key(keys, subs, sources, dests, change_account, extra, tx, tx_key, tx_keys, true /* rct */, config, true /* view_tags */))
            return tx_error(error::tx_failed); 

          auto details = std::make_shared<backend::transaction>();
          details->raw_bytes = epee::byte_slice{cryptonote::t_serializable_object_to_blob(tx)};
          details->timestamp = std::chrono::system_clock::now();
          details->amount = std::accumulate(amount->begin(), amount->end(), std::uint64_t(0));
          details->fee = get_tx_fee(tx);
          details->direction = Monero::TransactionInfo::Direction_Out;
          if (extra_nonce.size() == sizeof(crypto::hash8))
          {
            crypto::hash8 pid{};
            std::memcpy(std::addressof(pid), extra_nonce.data(), sizeof(pid));
            details->payment_id = pid;
          }
          get_transaction_hash(tx, details->id);
          get_transaction_prefix_hash(tx, details->prefix);

          if (sources.size() != tx.vin.size())
            throw std::logic_error{"Sanity check: sources.size() == tx.vin.size()"};

          for (std::size_t i = 0; i < sources.size(); ++i)
          {
            const auto& source = sources.at(i);
            auto spend = details->spends.try_emplace(boost::get<cryptonote::txin_to_key>(tx.vin.at(i)).k_image).first;
            spend->second.amount = source.amount;
            spend->second.output_pub = rct2pk(source.outputs.at(source.real_output).second.dest);

            const auto elem = std::find_if(spending.begin(), spending.end(), [&] (const auto& e) {
              return e.first == spend->second.output_pub;
            });
            if (elem == spending.end())
              throw std::logic_error{"Sanity check spend not found"};

            const auto& base = elem->second->receives.at(spend->second.output_pub);
            spend->second.sender = base.recipient;
            spend->second.tx_pub = base.tx_pub;
          }

          if (dests.size() != tx.vout.size())
            throw std::logic_error{"Sanity check: dests.size() == tx.vout.size()"};
          if (dests.size() != tx.rct_signatures.ecdhInfo.size())
            throw std::logic_error{"Sanity check: dests.size() == ecdhInfo.size()"};
          if (!tx_keys.empty() && tx_keys.size() != dests.size())
            throw std::logic_error{"Sanity check tx_keys.empty() || tx_keys.size() == dest.size()"};

          struct get_output_pub
          {
            crypto::public_key operator()(const cryptonote::txout_to_script&) const noexcept { return {}; }
            crypto::public_key operator()(const cryptonote::txout_to_scripthash&) const noexcept { return {}; }
            crypto::public_key operator()(const cryptonote::txout_to_key& src) const noexcept { return src.key; }
            crypto::public_key operator()(const cryptonote::txout_to_tagged_key& src) const noexcept { return src.key; }
          };

          for (std::size_t i = 0; i < dests.size(); ++i)
          {
            const auto& dest = dests.at(i);
            if (dest.original != change_address)
              continue;

            auto receive = details->receives.try_emplace(
              boost::apply_visitor(get_output_pub{}, tx.vout.at(i).target)
            ).first;

            receive->second.global_index = std::numeric_limits<std::uint64_t>::max();
            receive->second.amount = dest.amount;
            receive->second.recipient = {subaddr_account, 0};
            receive->second.index = i;
            receive->second.rct_mask = tx.rct_signatures.ecdhInfo.at(i).mask; 

            if (tx_keys.empty())
              crypto::secret_key_to_public_key(tx_key, receive->second.tx_pub);
            else
              crypto::secret_key_to_public_key(tx_keys.at(i), receive->second.tx_pub);
          }

          if (!tx_keys.empty())
          {             
            if (tx_keys.size() != dests.size())
              throw std::logic_error{"Failed sanity check: tx_keys.size() == dests.size()"};

            for (std::size_t i = 0; i < tx_keys.size(); ++i)
            {
              const auto& dest = dests.at(i);
              const auto is_transfer = transfers.find({dest.amount, dest.original});
              if (is_transfer == transfers.end())
                continue;

              details->transfers.emplace_back(dest.original, dest.amount).secret = tx_keys.at(i);
              transfers.erase(is_transfer);
            }

            if (!transfers.empty())
              throw std::logic_error{"Sanity check: missing secret key for outgoing transfer"};
          }
          else
          {
            for (auto& transfer : transfers)
              details->transfers.emplace_back(transfer.second, transfer.first).secret = tx_key;
            transfers.clear();
          }

          return std::make_unique<internal::pending_transaction>(data_, std::move(tx), std::move(details));
        }();
    }
    catch (const std::exception & e)
    {
      set_critical(e);
      out = tx_error(error::tx_critical);
    }

    return out.release();
  }

  Monero::PendingTransaction* wallet::createTransaction(const std::string &dst_addr, const std::string &payment_id,
                                                   std::optional<uint64_t> amount, uint32_t mixin_count,
                                                   Monero::PendingTransaction::Priority priority,
                                                   uint32_t subaddr_account,
                                                   std::set<uint32_t> subaddr_indices)
  {
    return createTransactionMultDest({dst_addr}, payment_id, amount ? std::optional<std::vector<uint64_t>>{{*amount}} : std::nullopt, mixin_count, priority, subaddr_account, subaddr_indices);
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
      subaddress_minor_ = std::make_unique<subaddress_minor>(this, data_);
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
      subaddresses_ = std::make_unique<subaddress_account>(this, data_);
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

    for (const auto& transfer : iter->second->transfers)
    {
      out.insert(out.end(), hex_size, 0);
      if (!epee::to_hex::buffer({out.data() + out.size() - hex_size, hex_size}, epee::as_byte_span(unwrap(unwrap(transfer.secret)))))
      {
        set_critical(std::runtime_error{"getTxKey conversion to hex failure"});
        return {};
      }
    }

    return out;
  }
}} // lwsf // internal
