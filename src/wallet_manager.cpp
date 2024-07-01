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

#include "lws_frontend.h"

#include <chrono>
#include <memory>
#include <string>
#include <system_error>
#include "backend.h"
#include "lwsf_config.h"
#include "net/http_client.h"   // monero/contrib/epee/include
#include "net/parse.h"         // monero/src
#include "net/socks_connect.h" // monero/src
#include "rpc.h"
#include "wallet.h"

namespace lwsf
{
  namespace internal
  {
    //! \TODO Mark final when completely implemented
    class wallet_manager : public lwsf::WalletManager
    {
      rpc::http_client client_;
      std::string error_;
      rpc::daemon_status cached_;
      std::chrono::steady_clock::time_point cached_last_;

      rpc::daemon_status get_daemon_status()
      {
        if (std::chrono::steady_clock::now() - cached_last_ > config::daemon_status_cache)
        {
          const auto resp = rpc::invoke<rpc::daemon_status>(client_, rpc::empty{});
          if (!resp)
          {
            error_ = resp.error().message();
            cached_ = rpc::daemon_status{};
          }
          else
          {
            error_.clear();
            cached_ = std::move(*resp);
          }
        }
        return cached_;
      }

    public:

      wallet_manager()
        : client_(), error_(), cached_{}, cached_last_(std::chrono::seconds{0})
      {}

      virtual ~wallet_manager() override
      {}

    /*!
     * \brief  Creates new wallet
     * \param  path           Name of wallet file
     * \param  password       Password of wallet file
     * \param  language       Language to be used to generate electrum seed mnemonic
     * \param  nettype        Network type
     * \param  kdf_rounds     Number of rounds for key derivation function
     * \return                Wallet instance (Wallet::status() needs to be called to check if created successfully)
     */
      std::unique_ptr<Wallet> createWallet(const std::string &path, const std::string &password, const std::string &language, NetworkType nettype, uint64_t kdf_rounds) override
      {
        //! \TODO Complete
        return std::make_unique<wallet>(path, std::make_shared<backend::wallet>(true));
      }

    /*!
     * \brief  Opens existing wallet
     * \param  path           Name of wallet file
     * \param  password       Password of wallet file
     * \param  nettype        Network type
     * \param  kdf_rounds     Number of rounds for key derivation function
     * \param  listener       Wallet listener to set to the wallet after creation
     * \return                Wallet instance (Wallet::status() needs to be called to check if opened successfully)
     */

      std::unique_ptr<Wallet> openWallet(const std::string &path, const std::string &password, NetworkType nettype, uint64_t kdf_rounds, std::shared_ptr<WalletListener> listener) override
      {
        //! \TODO Complete
      }

    /*!
     * \brief  recovers existing wallet using mnemonic (electrum seed)
     * \param  path           Name of wallet file to be created
     * \param  password       Password of wallet file
     * \param  mnemonic       mnemonic (25 words electrum seed)
     * \param  nettype        Network type
     * \param  restoreHeight  restore from start height
     * \param  kdf_rounds     Number of rounds for key derivation function
     * \param  seed_offset    Seed offset passphrase (optional)
     * \return                Wallet instance (Wallet::status() needs to be called to check if recovered successfully)
     */
      std::unique_ptr<Wallet> recoveryWallet(const std::string &path, const std::string &password, const std::string &mnemonic,
                                             NetworkType nettype = MAINNET, uint64_t restoreHeight = 0, uint64_t kdf_rounds = 1,
                                             const std::string &seed_offset = {}) override final
      {
        //! \TODO Complete
      }

    /*!
     * \deprecated this method creates a wallet WITHOUT a passphrase, use the alternate recoverWallet() method
     * \brief  recovers existing wallet using mnemonic (electrum seed)
     * \param  path           Name of wallet file to be created
     * \param  mnemonic       mnemonic (25 words electrum seed)
     * \param  nettype        Network type
     * \param  restoreHeight  restore from start height
     * \return                Wallet instance (Wallet::status() needs to be called to check if recovered successfully)
     */
      std::unique_ptr<Wallet> recoveryWallet(const std::string &path, const std::string &mnemonic, NetworkType nettype, uint64_t restoreHeight = 0) override
      {
      }

    /*!
     * \brief  recovers existing wallet using keys. Creates a view only wallet if spend key is omitted
     * \param  path           Name of wallet file to be created
     * \param  password       Password of wallet file
     * \param  language       language
     * \param  nettype        Network type
     * \param  restoreHeight  restore from start height
     * \param  addressString  public address
     * \param  viewKeyString  view key
     * \param  spendKeyString spend key (optional)
     * \param  kdf_rounds     Number of rounds for key derivation function
     * \return                Wallet instance (Wallet::status() needs to be called to check if recovered successfully)
     */
      std::unique_ptr<Wallet> createWalletFromKeys(const std::string &path,
                                                   const std::string &password,
                                                   const std::string &language,
                                                   NetworkType nettype,
                                                   uint64_t restoreHeight,
                                                   const std::string &addressString,
                                                   const std::string &viewKeyString,
                                                   const std::string &spendKeyString,
                                                   uint64_t kdf_rounds) override
      {
        //! \TODO Complete
      }

   /*!
    * \deprecated this method creates a wallet WITHOUT a passphrase, use createWalletFromKeys(..., password, ...) instead
    * \brief  recovers existing wallet using keys. Creates a view only wallet if spend key is omitted
    * \param  path           Name of wallet file to be created
    * \param  language       language
    * \param  nettype        Network type
    * \param  restoreHeight  restore from start height
    * \param  addressString  public address
    * \param  viewKeyString  view key
    * \param  spendKeyString spend key (optional)
    * \return                Wallet instance (Wallet::status() needs to be called to check if recovered successfully)
    */
      std::unique_ptr<Wallet> createWalletFromKeys(const std::string &path, 
                                                   const std::string &language,
                                                   NetworkType nettype, 
                                                   uint64_t restoreHeight,
                                                   const std::string &addressString,
                                                   const std::string &viewKeyString,
                                                   const std::string &spendKeyString) override
      {
        //! \TODO Complete
      }

    /*!
     * \brief  creates wallet using hardware device.
     * \param  path                 Name of wallet file to be created
     * \param  password             Password of wallet file
     * \param  nettype              Network type
     * \param  deviceName           Device name
     * \param  restoreHeight        restore from start height (0 sets to current height)
     * \param  subaddressLookahead  Size of subaddress lookahead (empty sets to some default low value)
     * \param  kdf_rounds           Number of rounds for key derivation function
     * \param  listener             Wallet listener to set to the wallet after creation
     * \return                      Wallet instance (Wallet::status() needs to be called to check if recovered successfully)
     */
      std::unique_ptr<Wallet> createWalletFromDevice(const std::string &path,
                                            const std::string &password,
                                            NetworkType nettype,
                                            const std::string &deviceName,
                                            uint64_t restoreHeight,
                                            const std::string &subaddressLookahead,
                                            uint64_t kdf_rounds,
                                            WalletListener * listener) override
      {
        //! \TODO Complete
      }

    /*!
     * \brief Closes wallet. In case operation succeeded, wallet object deleted. in case operation failed, wallet object not deleted
     * \param wallet        previously opened / created wallet instance
     * \return              None
     */
      bool closeWallet(std::unique_ptr<Wallet> wallet, bool store) override
      {
        if (wallet && store)
          wallet->store(wallet->filename());
      }

    /*
     * ! checks if wallet with the given name already exists
     */

    /*!
     * @brief TODO: delme walletExists - check if the given filename is the wallet
     * @param path - filename
     * @return - true if wallet exists
     */
      bool walletExists(const std::string &path) override
      {
        //! \TODO Complete
      }

    /*!
     * @brief verifyWalletPassword - check if the given filename is the wallet
     * @param keys_file_name - location of keys file
     * @param password - password to verify
     * @param no_spend_key - verify only view keys?
     * @param kdf_rounds - number of rounds for key derivation function
     * @return - true if password is correct
     *
     * @note
     * This function will fail when the wallet keys file is opened because the wallet program locks the keys file.
     * In this case, Wallet::unlockKeysFile() and Wallet::lockKeysFile() need to be called before and after the call to this function, respectively.
     */
      bool verifyWalletPassword(const std::string &keys_file_name, const std::string &password, bool no_spend_key, uint64_t kdf_rounds) const override
      {
        //! \TODO Complete
      }

    /*!
     * \brief determine the key storage for the specified wallet file
     * \param device_type     (OUT) wallet backend as enumerated in Wallet::Device
     * \param keys_file_name  Keys file to verify password for
     * \param password        Password to verify
     * \return                true if password correct, else false
     *
     * for verification only - determines key storage hardware
     *
     */
      bool queryWalletDevice(Wallet::Device& device_type, const std::string &keys_file_name, const std::string &password, uint64_t kdf_rounds) const override
      {
        //! \TODO Complete
      }

    /*!
     * \brief findWallets - searches for the wallet files by given path name recursively
     * \param path - starting point to search
     * \return - list of strings with found wallets (absolute paths);
     */
      std::vector<std::string> findWallets(const std::string &path) override
      {
        //! \TODO Complete
      }

      std::string errorString() const override { return error_; }

    //! set the daemon address (hostname and port)
      void setDaemonAddress(const std::string &address) override
      {
        //! \TODO Complete
      }

    //! returns whether the daemon can be reached, and its version number
      bool connected(uint32_t *version = NULL) override
      {
        version = 0;
        return client_.is_connected();
      }

      uint64_t blockchainHeight() override
      {
        return get_daemon_status().height;
      }

      uint64_t blockchainTargetHeight() override
      {
        return get_daemon_status().target_height;
      }

        //! \TODO Complete
      uint64_t networkDifficulty() override { return 0; }

        //! \TODO Complete
      double miningHashRate() override { return 0.f; }

        //! \TODO Complete
      uint64_t blockTarget() override { return 0; }

      bool isMining() override { return false; }
      bool startMining(const std::string&, uint32_t, bool, bool) override
      {
        return false;
      }
      bool stopMining() override { return true; }

      std::string resolveOpenAlias(const std::string &address, bool &dnssec_valid) const override
      {
        //! \TODO Complete
      }

    //! checks for an update and returns version, hash and url
    static std::tuple<bool, std::string, std::string, std::string, std::string> checkUpdates(
        const std::string &software,
        std::string subdir,
        const char *buildtag = nullptr,
        const char *current_version = nullptr);

      bool setProxy(const std::string &address) override
      {
        auto endpoint = net::get_tcp_endpoint(address);
        if (!endpoint)
        {
          error_ = endpoint.error().message();
          return false;
        }
        client_.set_connector(net::socks::connector{std::move(*endpoint)});
        return true;
      }
    };
  } // internal

  std::unique_ptr<WalletManager> WalletManagerFactory::getWalletManager()
  {
    return std::make_unique<internal::wallet_manager>();
  }

  void WalletManagerFactory::setLogLevel(int level)
  {
        //! \TODO Complete
  }
   
  void WalletManagerFactory::setLogCategories(const std::string &categories)
  {
        //! \TODO Complete
  }
} // lwsf
