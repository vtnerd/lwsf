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
#include <boost/range/combine.hpp>
#include <exception>
#include <filesystem>
#include <sodium/core.h>
#include <sodium/randombytes.h>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include "address_book.h"
#include "backend.h"
#include "common/expect.h"                            // monero/src
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "cryptonote_config.h"                        // monero/src
#include "cryptonote_core/cryptonote_tx_utils.h"      // monero/src
#include "error.h"
#include "hex.h" // monero/contrib/epee/include
#include "lwsf_config.h"
#include "mnemonics/electrum-words.h" // monero/src
#include "net/net_parse_helpers.h" // monero/contrib/epee/include
#include "net/parse.h"         // monero/src
#include "net/socks.h"         // monero/src
#include "net/socks_connect.h" // monero/src
#include "numeric.h"
#include "pending_transaction.h"
#include "subaddress_account.h"
#include "subaddress_minor.h"
#include "transaction_history.h"
#include "utils/encrypted_file.h"
#include "wire.h"
#include "wire/msgpack.h"

//! Runtime-check (assertion) for tx construction
#define LWSF_TX_VERIFY(x) \
  do                      \
  {                       \
    if (!(x))             \
      throw std::logic_error{"Tx construction assertion failed (line " + std::to_string(__LINE__) + "): " + #x}; \
  } while (0)

namespace lwsf { namespace internal
{ 
  namespace
  {
    //! The stored wallet file always has this at beginning
    static constexpr std::string_view wallet_file_magic{"lwsf-wallet-1.0"};

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

    std::uint64_t calculate_fee_from_weight(const std::uint64_t base_fee, const std::uint64_t weight, const std::uint64_t fee_quantization_mask) noexcept
    {
      uint64_t fee = weight * base_fee;
      fee = (fee + fee_quantization_mask - 1) / fee_quantization_mask * fee_quantization_mask;
      return fee;
    }

    std::size_t estimate_rct_tx_size(const std::size_t n_inputs, const std::size_t n_outputs, const std::uint32_t mixin, const std::size_t extra_size) noexcept
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
      if (!extra_size && n_outputs <= 2)
        size += 3 + sizeof(crypto::hash8);

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

    std::uint64_t estimate_tx_weight(const std::size_t n_inputs, const std::size_t n_outputs, const std::uint32_t mixin, const std::size_t extra_size) noexcept
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

    std::uint64_t estimate_fee(const std::uint64_t base_fee, const std::size_t n_inputs, const std::size_t n_outputs, const std::uint32_t mixin, const std::size_t extra_size, const std::uint64_t fee_mask) noexcept
    {
      return calculate_fee_from_weight(base_fee, estimate_tx_weight(n_inputs, n_outputs, mixin, extra_size), fee_mask);
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

    class need_more_sources final : public std::exception
    {
      std::uint64_t fee_;
    public:
      explicit need_more_sources(const std::uint64_t fee) noexcept
        : std::exception(), fee_(fee)
      {}

      std::uint64_t fee() const noexcept { return fee_; }
      const char* what() const noexcept override { return "need_more_sources"; }
    };

    struct unknown_exception : std::exception
    {
      unknown_exception() noexcept
        : std::exception()
      {}

      const char* what() const noexcept override { return "unknown error"; }
    };

    constexpr boost::chrono::nanoseconds to_boost(const std::chrono::nanoseconds source) noexcept
    {
      // types could differ - verify they can represent all the same values
      using boost_rep = boost::chrono::nanoseconds::rep;
      using std_rep = std::chrono::nanoseconds::rep;
      static_assert(std::is_integral<boost_rep>());
      static_assert(std::is_integral<std_rep>());
      static_assert(std::is_signed<boost_rep>());
      static_assert(std::is_signed<std_rep>());
      static_assert(std::numeric_limits<boost_rep>::min() == std::numeric_limits<std_rep>::min());
      static_assert(std::numeric_limits<boost_rep>::max() == std::numeric_limits<std_rep>::max());
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
    return !try_load(path, wallet_file_magic).empty();
  }

  bool wallet::verify_password(std::string path, const std::string& password)
  {
    // We don't use a separate keys file, remove the suffix is present
    static constexpr const std::string_view keys_suffix{".keys"};
    if (keys_suffix.size() <= path.size() && std::string_view{path.data() + path.size() - keys_suffix.size()} == keys_suffix)
      path.erase(path.size() - keys_suffix.size());

    epee::byte_slice file = try_load(path, wallet_file_magic);
    if (file.empty())
      return false;
    return bool(decrypt(try_load(path, wallet_file_magic), epee::strspan<std::uint8_t>(password)));
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
        if (!try_load(filename, wallet_file_magic).empty())
          out.push_back(std::move(filename));
      }
    }
    return out;
  }

  wallet::wallet(error, std::string msg)
    : data_(std::make_shared<backend::wallet>()),
      addressbook_(),
      history_(),
      subaddresses_(),
      subaddress_minor_(),
      filename_(),
      password_(),
      work_queue_(),
      exception_error_(std::move(msg)),
      error_(),
      thread_(),
      iterations_(1),
      mixin_(config::mixin_default),
      refresh_interval_(config::refresh_interval),
      refresh_notify_(),
      error_sync_(),
      refresh_sync_(),
      thread_sync_(),
      thread_state_(state::stop),
      mandatory_refresh_(false)
  {}

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
      epee::byte_slice file = try_load(filename_ + ".new", wallet_file_magic);
      if (file.empty())
        file = try_load(filename_, wallet_file_magic);

      if (file.empty())
        throw std::runtime_error{"Unable to open wallet file " + filename_};

      if (std::error_code error = data_->from_bytes(decrypt(std::move(file), epee::strspan<std::uint8_t>(password_)).value()))
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

  wallet::wallet(from_keys, const Monero::NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds, const boost::optional<crypto::secret_key>& view_key, const boost::optional<crypto::secret_key>& spend_key)
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

    if (!view_key)
    {
      exception_error_ = "view_key is invalid";
      return;
    }

    if (!spend_key)
    {
      exception_error_ = "spend_key is invalid";
      return;
    }

    data_->primary.generated_locally = false;
    data_->primary.type = nettype;
    data_->primary.view.sec = *view_key;
    data_->primary.spend.sec = *spend_key;
 
    if (!crypto::secret_key_to_public_key(data_->primary.view.sec, data_->primary.view.pub))
    {
      exception_error_ = "view_pub could not be computed";
      return;
    }

    if (!crypto::secret_key_to_public_key(data_->primary.spend.sec, data_->primary.spend.pub))
    {
      exception_error_ = "spend_pub could not be computed";
      return;
    }
  }

  namespace
  {
    boost::optional<crypto::secret_key> to_secret_key(const std::string& hex)
    {
      crypto::secret_key out{};
      if (!epee::from_hex::to_buffer(epee::as_mut_byte_span(unwrap(unwrap(out))), hex))
	return boost::none;
      return out;
    }
  }

  wallet::wallet(from_keys, const Monero::NetworkType nettype, std::string filename, std::string password, const std::uint64_t kdf_rounds, const std::string& address_string, const std::string& view_key, const std::string& spend_key)
    : wallet(from_keys{}, nettype, std::move(filename), std::move(password), kdf_rounds, to_secret_key(view_key), to_secret_key(spend_key))
  {
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
      const std::filesystem::path file = real_path;
      const std::filesystem::path new_file = real_path + ".new";
      const std::filesystem::path directory =
        std::filesystem::path{real_path}.remove_filename();

      if (std::filesystem::exists(new_file))
        std::filesystem::rename(new_file, file);

      // blocks until file and directory contents are synced
      epee::byte_slice blob =
        encrypt(wallet_file_magic, data_->to_bytes().value(), iterations_, epee::strspan<std::uint8_t>(password_)).value();
      if (!atomic_file_write(new_file, directory, std::move(blob)))
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
    queue_work([this, height] () { return data_->restore_height(height).error(); });
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

#ifdef LWSF_POLYSEED_ENABLE
  void wallet::setPolyseed(epee::byte_slice seed, std::string passphrase)
  {
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    data_->primary.poly = backend::account::polyseed{std::move(seed), std::move(passphrase)};
  }

  bool wallet::getPolyseed(std::string &seed, std::string &passphrase) const
  {
    struct release_polyseed
    {
      void operator()(polyseed_data* ptr) const noexcept
      {
        if (ptr) polyseed_free(ptr);
      }
    };

    std::unique_ptr<polyseed_data, release_polyseed> cleanup{};

    seed.clear();
    passphrase.clear();

    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (!data_->primary.poly)
      return false;
    if (data_->primary.poly->seed.size() != sizeof(polyseed_storage))
      return false;
   
    polyseed_data* temp = nullptr;
    if (polyseed_load(data_->primary.poly->seed.data(), &temp) != POLYSEED_OK)
      return false;
    cleanup.reset(temp);

    const polyseed_lang* lang = nullptr;
    const int langs = polyseed_get_num_langs();
    for (int i = 0; i < langs; ++i)
    {
      lang = polyseed_get_lang(i);
      if (lang && polyseed_get_lang_name(lang) == data_->primary.language)
	break;
    }

    if (!lang)
      return false;

    seed.resize(POLYSEED_STR_SIZE);
    seed.resize(polyseed_encode(temp, lang, POLYSEED_MONERO, &seed[0]));
    passphrase = data_->primary.poly->passphrase;
    return true;
  }
#endif // LWSF_POLYSEED_ENABLE

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
                                                   const Monero::PendingTransaction::Priority priority,
                                                   const uint32_t subaddr_account,
                                                   std::set<uint32_t> subaddr_indices)
  {
    using destinations_vector = std::vector<cryptonote::tx_destination_entry>;
    using transfers_map = std::multiset<std::pair<std::uint64_t, std::string>>;
    using unspent_map =
      std::unordered_map<crypto::public_key, std::pair<std::pair<std::uint64_t, std::uint64_t>, std::shared_ptr<const backend::transaction>>>;
    using unspent_by_amount_map =
      std::map<std::pair<std::uint64_t, std::uint64_t>, std::pair<crypto::public_key, std::shared_ptr<const backend::transaction>>>;

    // default priority not handled like standard wallet
    static_assert(Monero::PendingTransaction::Priority_Default == 0);
    static_assert(Monero::PendingTransaction::Priority_Medium == 2);

    const bool subtract_from_dest = !amount;
    const unsigned priority_int = priority <= 0 ? 2 : unsigned(priority) - 1;
    if (!mixin_count)
      mixin_count = mixin_;

    std::unique_ptr<internal::pending_transaction> out;
    const auto throw_low_funds = [] ()
    {
      throw std::runtime_error{"Unlocked funds too low"};
    };

    try
    {
      /* This design is funky, but guards against exceptions in destructors
      of stack elements. Everything on the stack (except for arguments) is
      cleaned up before the uniue_ptr is released. */
      out = [&, this] ()
        {
          if (!amount && dst_addr.size() > 1)
            throw std::invalid_argument{"Sweep requested with multiple destinations"};
          if (amount && (*amount).size() != dst_addr.size())
            throw std::invalid_argument{"Must have equal amounts and destinations"};
          if (amount && (*amount).empty())
            throw std::invalid_argument{"Zero destinations only valid with empty amounts"};
          if (!payment_id.empty())
            throw std::invalid_argument{"Long payment id was provided - deprecated"};

          cryptonote::network_type ctype{};
          Monero::NetworkType mtype{};
          std::uint64_t per_byte_fee = 0;
          std::uint64_t fee_mask = 0;
          std::string change_address{};
          cryptonote::account_keys keys{};
          cryptonote::account_public_address change_account{};
          unspent_map unspent{};
          {
            data_->refresh(); // get latest outputs, block height, and fee info

            const boost::lock_guard<boost::mutex> lock{data_->sync};
            fee_mask = data_->fee_mask;

            if (data_->per_byte_fee.empty() || !fee_mask || !data_->passed_login)
              throw std::system_error{data_->refresh_error, "Tx construction"};

            if (data_->per_byte_fee.size() <= priority_int)
              per_byte_fee = data_->per_byte_fee.back();
            else
              per_byte_fee = data_->per_byte_fee[priority_int];

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
 
          // By copy to catch mutations (want each invoke to be consistent)
          const auto gather_sources_and_construct_tx =
            [=] (unspent_by_amount_map unspent_by_amount, destinations_vector dests, const transfers_map& transfers, const std::string& extra_nonce, const std::uint64_t min_fee)
              -> std::shared_ptr<backend::transaction>
          {
            // leave 1 spot for change
            LWSF_TX_VERIFY(!dests.empty());
            LWSF_TX_VERIFY(dests.size() < config::max_outputs_in_construction);
            LWSF_TX_VERIFY(dests.size() == transfers.size());

            safe_uint64_t transfer_total{};
            for (const auto& e : dests)
              transfer_total += e.amount;

            std::vector<std::uint8_t> extra;
            if (!extra_nonce.empty() && !cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce))
              throw std::runtime_error{"cryptonote:add_extra_nonce_to_tx_extra failed"};

            bool has_change = false;
            std::vector<std::pair<crypto::public_key, std::shared_ptr<const backend::transaction>>> spending;
            {
              const auto is_rct = [] (const unspent_by_amount_map::iterator output)
              {
                return bool(output->second.second->receives.at(output->second.first).rct_mask);
              };

              bool all_rct = true;
              std::uint64_t fee = 1;
              std::uint64_t remaining = transfer_total;
              while (bool(remaining + fee))
              {
                if (unspent_by_amount.empty())
                {
                  if (subtract_from_dest && !remaining)
                    break;
                  throw_low_funds();
                }

                /* Check if we can omit change address for more efficiency. We
                  must have at least 2 outputs for uniformity/privacy. */
                if (1 < dests.size())
                {
                  fee = estimate_fee(per_byte_fee, spending.size() + 1, dests.size(), mixin_count, extra.size(), fee_mask);
                  fee = std::max(min_fee, fee);
                  const std::uint64_t needed = remaining + fee;
                  const auto output = unspent_by_amount.lower_bound({needed, 0});
                  if (output != unspent_by_amount.end() && needed == output->first.first)
                  {
                    remaining = 0;
                    all_rct &= is_rct(output);
                    spending.emplace_back(output->second.first, output->second.second);
                    unspent_by_amount.erase(output);
                    break;
                  }
                }

                // check
                fee = estimate_fee(per_byte_fee, spending.size() + 1, dests.size() + 1, mixin_count, extra.size(), fee_mask);
                fee = std::max(min_fee, fee);

                const std::uint64_t needed = remaining + fee;
                auto output = unspent_by_amount.lower_bound({needed, 0});
                if (output == unspent_by_amount.end())
                  --output;

                const std::uint64_t this_amount = output->first.first;
                const bool complete = needed <= this_amount;
                all_rct &= is_rct(output);
                spending.emplace_back(output->second.first, output->second.second);
                unspent_by_amount.erase(output);

                remaining -= this_amount;
                if (complete)
                  break;
              }

              // merge lowest dust into a 2of2 tx
              if (all_rct && spending.size() <= 1)
              {
                for (auto output = unspent_by_amount.begin(); output != unspent_by_amount.end(); ++output)
                {
                  if (is_rct(output))
                  {
                    remaining -= output->first.first;
                    spending.emplace_back(output->second.first, output->second.second);
                    unspent_by_amount.erase(output);
                    break;
                  }
                }
              }

              if (subtract_from_dest)
              {
                LWSF_TX_VERIFY(dests.size() == 1);
                if (dests.back().amount < fee)
                  throw_low_funds();
                dests.back().amount -= fee;
                fee = 0;
              }

              const std::uint64_t change = (std::uint64_t(0) - remaining) - fee;
              if (change || dests.size() == 1)
              {
                has_change = true;
                auto& change_dest = dests.emplace_back();
                change_dest.original = change_address;
                change_dest.addr = change_account;
                change_dest.amount = change;
                change_dest.is_subaddress = bool(subaddr_account);
                change_dest.is_integrated = false;
              }

              LWSF_TX_VERIFY(config::min_outputs <= dests.size());

              // verify SUM(input) = SUM(output) - fee

              remaining = 0;
              for (const auto& source : spending)
              {
                const auto output = source.second->receives.find(source.first);
                LWSF_TX_VERIFY(output != source.second->receives.end());
                remaining += output->second.amount;
              }

              for (const auto& dest : dests)
                remaining -= dest.amount;

              LWSF_TX_VERIFY(fee == remaining);
            }

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
                throw std::system_error{resp.error()};
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
                  throw std::runtime_error{"Missing requested decoys"};

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
            for (auto& source : sources)
            {
              LWSF_TX_VERIFY(!source.outputs.empty());

              const std::uint64_t real_source = source.outputs.front().first;
              std::sort(source.outputs.begin(), source.outputs.end(), ring_sort);
              LWSF_TX_VERIFY(std::unique(source.outputs.begin(), source.outputs.end(), ring_compare) == source.outputs.end());

              for (std::size_t i = 0; i < source.outputs.size(); ++i)
              {
                if (source.outputs.at(i).first == real_source)
                {
                  source.real_output = i;
                  break;
                }
              }
            }

            // By copy to catch mutations (want each invoke to be consistent)
            const auto construct_tx = [=, &dests, &sources = std::as_const(sources)] ()
              -> std::shared_ptr<backend::transaction>
            {
              auto rsources = sources; // already shuffled above
              auto rdests = dests; // in case we need to retry fee
              std::shuffle(rdests.begin(), rdests.end(), crypto::random_device{});

              static constexpr const rct::RCTConfig config{
                rct::RangeProofPaddedBulletproof, config::bulletproof_version
              };

              crypto::secret_key tx_key;
              std::vector<crypto::secret_key> tx_keys;
              cryptonote::transaction tx;
              LWSF_TX_VERIFY(config::min_outputs <= rdests.size());
              LWSF_TX_VERIFY(rdests.size() <= config::max_outputs_in_construction);
              if (!cryptonote::construct_tx_and_get_tx_key(keys, subs, rsources, rdests, change_account, extra, tx, tx_key, tx_keys, true /* rct */, config, true /* view_tags */))
                throw std::runtime_error{"cryptonote::construct_tx_and_get_tx_key failed"};

              /* Collect all information for `backend::transaction` - this
                helps with UI as the transaction will appear immediately when
                `pending_transaction->commit()` is performed. */

              auto details = std::make_shared<backend::transaction>();
              details->raw_bytes = epee::byte_slice{cryptonote::t_serializable_object_to_blob(tx)};
              details->timestamp = std::chrono::system_clock::now();
              details->amount = transfer_total;
              details->fee = get_tx_fee(tx);

              const std::uint64_t weight = get_transaction_weight(tx, details->raw_bytes.size());
              const std::uint64_t real_fee = calculate_fee_from_weight(per_byte_fee, weight, fee_mask);

              const auto get_change_index = [&] () -> std::size_t
              {
                LWSF_TX_VERIFY(!dests.empty());
                if (subtract_from_dest)
                  return 0;
                if (has_change && dests.back().original == change_address)
                  return dests.size() - 1;
                throw need_more_sources{real_fee}; // skipped change address
              };

              if (details->fee < real_fee)
              {
                const std::uint64_t diff = real_fee - details->fee;
                auto& dest = dests.at(get_change_index());
                if (dest.amount < diff)
                  throw need_more_sources{real_fee};
                dest.amount -= diff;
                return nullptr; // retry construction with updated `dests`
              }
              else if (details->fee > real_fee)
              {
                const std::uint64_t diff = details->fee - real_fee;
                dests.at(get_change_index()).amount += diff;
                return nullptr; // retry construction with updated `dests`
              }
              // else `details->fee == real_fee`

              details->direction = Monero::TransactionInfo::Direction_Out;
              if (extra_nonce.size() == sizeof(crypto::hash8) + 1)
              {
                crypto::hash8 pid{};
                std::memcpy(std::addressof(pid), extra_nonce.data() + 1, sizeof(pid));
                details->payment_id = pid;
              }
              get_transaction_hash(tx, details->id);
              get_transaction_prefix_hash(tx, details->prefix);

              LWSF_TX_VERIFY(rsources.size() == tx.vin.size());
              for (std::size_t i = 0; i < rsources.size(); ++i)
              {
                const auto& source = rsources.at(i);
                auto spend = details->spends.try_emplace(boost::get<cryptonote::txin_to_key>(tx.vin.at(i)).k_image).first;
                spend->second.amount = source.amount;
                spend->second.output_pub = rct2pk(source.outputs.at(source.real_output).second.dest);

                const auto elem = std::find_if(spending.begin(), spending.end(), [&] (const auto& e) {
                  return e.first == spend->second.output_pub;
                });
                LWSF_TX_VERIFY(elem != spending.end());

                const auto& base = elem->second->receives.at(spend->second.output_pub);
                spend->second.sender = base.recipient;
                spend->second.tx_pub = base.tx_pub;
              }

              LWSF_TX_VERIFY(rdests.size() == tx.vout.size());
              LWSF_TX_VERIFY(rdests.size() == tx.rct_signatures.ecdhInfo.size());
              LWSF_TX_VERIFY(tx_keys.empty() || tx_keys.size() == rdests.size());

              struct get_output_pub
              {
                crypto::public_key operator()(const cryptonote::txout_to_script&) const noexcept { return {}; }
                crypto::public_key operator()(const cryptonote::txout_to_scripthash&) const noexcept { return {}; }
                crypto::public_key operator()(const cryptonote::txout_to_key& src) const noexcept { return src.key; }
                crypto::public_key operator()(const cryptonote::txout_to_tagged_key& src) const noexcept { return src.key; }
              };

              for (std::size_t i = 0; i < rdests.size(); ++i)
              {
                const auto& dest = rdests.at(i);
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
                auto rtransfers = transfers;
                for (std::size_t i = 0; i < tx_keys.size(); ++i)
                {
                  const auto& dest = rdests.at(i);
                  const auto is_transfer = rtransfers.find({dest.amount, dest.original});
                  if (is_transfer == rtransfers.end())
                    continue;

                  details->transfers.emplace_back(dest.original, dest.amount).secret = tx_keys.at(i);
                  rtransfers.erase(is_transfer);
                }
                LWSF_TX_VERIFY(rtransfers.empty());
              }
              else
              {
                for (auto& transfer : transfers)
                  details->transfers.emplace_back(transfer.second, transfer.first).secret = tx_key;
              }

              return details;
            }; // end `construct_tx` lambda

            // only one retry should be needed
            for (unsigned attempt = 0; attempt < 2; ++attempt)
            {
              auto pending = construct_tx(); // throws if more sources needed
              if (pending)
                return pending;
              // else `dests` should've been modified for retry
            }
            LWSF_TX_VERIFY(false); // this should be unreachable
          }; // end `gather_sources_and_construct_tx` lamda

          const auto get_unspent_by_amount = [] (const unspent_map& unspent)
          {
            // actually sorted by amount then reverse index (see comment above)
            unspent_by_amount_map out;
            for (const auto& tx : unspent)
              out.try_emplace(tx.second.first).first->second = {tx.first, tx.second.second};
            return out;
          };

          if (subtract_from_dest)
          {
            std::uint64_t total_unspent = 0;
            for (const auto& tx : unspent)
            {
              const auto output = tx.second.second->receives.find(tx.first);
              LWSF_TX_VERIFY(output != tx.second.second->receives.end());
              total_unspent += output->second.amount;
            }
            amount = std::vector<std::uint64_t>{total_unspent};
          }

          std::string extra_nonce{};
          destinations_vector dests_flat{};
          transfers_map transfers_flat{};

          for (std::size_t i = 0; i < dst_addr.size(); ++i)
          {
            cryptonote::address_parse_info info{};
            if (!cryptonote::get_account_address_from_str(info, ctype, dst_addr.at(i)))
              throw std::invalid_argument{"Invalid destination address"};

            if (info.has_payment_id)
            {
              if (!extra_nonce.empty())
                throw std::invalid_argument{"Two payment ids provided"};
              cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, info.payment_id);
            }

            transfers_flat.insert({(*amount).at(i), dst_addr.at(i)});

            auto& dest = dests_flat.emplace_back();
            dest.original = dst_addr.at(i);
            dest.addr = info.address;
            dest.amount = (*amount).at(i);
            dest.is_subaddress = info.is_subaddress;
            dest.is_integrated = info.has_payment_id;
          }

          LWSF_TX_VERIFY(bool(amount));
          LWSF_TX_VERIFY(dst_addr.size() <= (*amount).size());
          for (std::size_t i = dst_addr.size(); i < (*amount).size(); ++i)
          {
            // this is a "self-sweep" (consolidation)
            auto& dest = dests_flat.emplace_back();
            dest.original = change_address;
            dest.addr = change_account;
            dest.amount = (*amount).at(i);
            dest.is_subaddress = subaddr_account;
            dest.is_integrated = false;
          }

          std::sort(dests_flat.begin(), dests_flat.end(), [] (const auto& lhs, const auto& rhs) {
            return lhs.amount < rhs.amount;
          });

          /* This function makes a crude attempt at breaking up destinations
            into multiple transactions IFF exceeding output maximum. The
            algorithm is crude, and does a best effort to minimize source/input
            usage. Unfortunately capture by reference, just much easier. */
          const auto get_and_update_destinations = [&] ()
          {
            // leave a spot for change
            LWSF_TX_VERIFY(dests_flat.size() == transfers_flat.size());
            if (dests_flat.size() < config::max_outputs_in_construction)
            {
              auto out = std::make_pair(std::move(dests_flat), std::move(transfers_flat));
              dests_flat.clear();
              transfers_flat.clear();
              return out;
            }

            // split //

            const std::size_t extra_size = extra_nonce.empty() ? 0 : extra_nonce.size() + 2;
            auto unspent_by_amount = get_unspent_by_amount(unspent);
            const std::size_t unspent_initial = unspent_by_amount.size();

            std::pair<destinations_vector, transfers_map> out{};

            const auto stop_condition = [&] ()
            {
              // leave one spot for change
              static_assert(1 <= config::max_outputs_in_construction);
              return dests_flat.empty() || std::get<0>(out).size() == config::max_outputs_in_construction - 1;
            };
            const auto update_transfers = [&] (const auto& dest)
            {
              auto transfer = transfers_flat.find({dest.amount, dest.original});
              LWSF_TX_VERIFY(transfer != transfers_flat.end());
              std::get<1>(out).insert(std::move(*transfer));
              transfers_flat.erase(transfer);
            };
            const auto by_amount = [] (const auto& lhs, const std::uint64_t rhs)
            {
              return lhs.amount < rhs;
            };

            std::uint64_t remaining = 0;
            while (!stop_condition())
            {
              // add largest amount first
              std::get<0>(out).push_back(std::move(dests_flat.back()));
              dests_flat.pop_back();
              update_transfers(std::get<0>(out).back());

              {
                const std::uint64_t amount = std::get<0>(out).back().amount;
                const std::size_t spend_size = unspent_initial - unspent_by_amount.size() + 1;
                const std::uint64_t fee =
                  estimate_fee(per_byte_fee, spend_size, std::get<0>(out).size() + 1, mixin_count, extra_size, fee_mask);
                const auto source = unspent_by_amount.lower_bound({amount + fee, 0});
                if (source == unspent_by_amount.end())
                  return out; // the "real" tx construction mechanism needs to run
                remaining += std::get<0>(source->first) - amount;
                unspent_by_amount.erase(source);
              }

              const std::size_t spend_size = unspent_initial - unspent_by_amount.size();
              while (!stop_condition())
              {
                const std::uint64_t fee =
                  estimate_fee(per_byte_fee, spend_size, std::get<0>(out).size() + 1, mixin_count, extra_size, fee_mask);
                if (remaining <= fee)
                  break;

                auto dest = std::lower_bound(dests_flat.begin(), dests_flat.end(), remaining - fee, by_amount);
                if (dest == dests_flat.end())
                  --dest;

                std::get<0>(out).push_back(std::move(*dest));
                dests_flat.erase(dest);
                update_transfers(std::get<0>(out).back());

                remaining -= std::get<0>(out).back().amount;
              }
            }

            return out;
          };

          std::vector<std::shared_ptr<backend::transaction>> pending;
          while (!dests_flat.empty())
          {
            std::uint64_t min_fee = 0;
            const auto dests = get_and_update_destinations(); // `dests_flat` pruned
            const auto unspent_by_amount = get_unspent_by_amount(unspent);

            unsigned attempt = 0;
            const std::size_t max_attempts = unspent.size();
            for (; attempt < max_attempts; ++attempt)
            {
              try
              {
                auto tx = gather_sources_and_construct_tx(unspent_by_amount, std::get<0>(dests), std::get<1>(dests), extra_nonce, min_fee);
                LWSF_TX_VERIFY(tx != nullptr);
                for (const auto& spend : tx->spends)
                  unspent.erase(spend.second.output_pub);
                pending.push_back(std::move(tx));
                break; // goto next tx
              }
              catch (const need_more_sources& e)
              {
                min_fee = std::max(min_fee, e.fee());
              }
            }

            if (attempt == max_attempts)
              throw_low_funds();
          }

          if (!dests_flat.empty())
            throw_low_funds();
          return std::make_unique<internal::pending_transaction>(data_, std::string{}, std::move(pending));
        }(); // end unnamed lambda encapsulating all tx construction

      LWSF_TX_VERIFY(out != nullptr);
    }
    catch (const std::exception& e)
    {
      out = std::make_unique<internal::pending_transaction>(data_, e.what());
    }

    return out.release();
  }

  Monero::PendingTransaction* wallet::createTransaction(const std::string &dst_addr, const std::string &payment_id,
                                                   Monero::optional<uint64_t> amount, uint32_t mixin_count,
                                                   Monero::PendingTransaction::Priority priority,
                                                   uint32_t subaddr_account,
                                                   std::set<uint32_t> subaddr_indices)
  {
    return createTransactionMultDest({dst_addr}, payment_id, amount ? Monero::optional<std::vector<uint64_t>>{{*amount}} : Monero::optional<std::vector<uint64_t>>{}, mixin_count, priority, subaddr_account, subaddr_indices);
  }

  bool wallet::submitTransaction(const std::string &fileName)
  {
    const auto tx = pending_transaction::load_from_file(data_, fileName);
    if (!tx)
      throw std::runtime_error{"Expected non-null from load_from_file"};
    return tx->status() == Monero::PendingTransaction::Status_Ok && tx->send();
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

    std::stringstream out;
    for (const auto& transfer : iter->second->transfers)
      epee::to_hex::buffer(out, epee::as_byte_span(unwrap(unwrap(transfer.secret))));

    return out.str();
  }

#ifndef LWSF_MASTER_ENABLE
  bool wallet::lightWalletLogin(bool &isNewWallet) const
  {
    isNewWallet = false;
    {
      const boost::lock_guard lock{data_->sync};
      if (data_->passed_login)
        return true;
    }

    const expect<bool> is_new = data_->login_is_new();
    if (!is_new)
      return false;
    isNewWallet = *is_new;
    return true;
  }

  bool wallet::lightWalletImportWalletRequest(std::string &payment_id, uint64_t &fee, bool &new_request, bool &request_fulfilled, std::string &payment_address, std::string &status)
  {
    expect<rpc::import_response> import = data_->restore_height(0);
    if (!import)
      return false;
    fee = std::uint64_t(import->import_fee.value_or(rpc::uint64_string(0)));
    new_request = import->new_request;
    request_fulfilled = import->request_fulfilled;
    payment_address = import->payment_address.value_or(std::string{});
    status = std::move(import->status);
    return true;
  }
#endif // LWSF_MASTER_ENABLE

}} // lwsf // internal
