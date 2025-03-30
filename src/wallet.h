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

#pragma once

#include "lws_frontend.h"

#include <atomic>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <memory>
#include <string>
#include "cryptonote_basic/account.h" // monero/src
#include "net/http_client.h"          // monero/contrib/epee/include
#include "wallet/api/wallet2_api.h"   // monero/src

namespace lwsf
{
namespace internal
{
  namespace backend { struct wallet; }


  //! \TODO Mark final when completely implemented
  class wallet : public Monero::Wallet
  {
    enum class state : std::uint8_t { stop = 0, paused, skip_once, run };

    const std::shared_ptr<backend::wallet> data_;
    std::unique_ptr<Monero::AddressBook> addressbook_;
    std::unique_ptr<Monero::TransactionHistory> history_;
    std::unique_ptr<Monero::SubaddressAccount> subaddresses_;
    const std::string filename_;
    std::string password_;
    mutable std::string exception_error_;
    mutable std::error_code status_;
    boost::thread thread_;
    const std::uint64_t iterations_;
    std::chrono::milliseconds refresh_interval_;  
    std::uint32_t mixin_;
    boost::condition_variable refresh_notify_;
    mutable boost::mutex error_sync_;
    boost::mutex refresh_sync_;
    state thread_state_;
    bool mandatory_refresh_;

    bool set_error(std::error_code status) const;
    void set_critical(const std::exception& e) const;

    void stop_refresh_loop();
    void refresh_loop();

  public:
    struct create_tag{};
    struct open_tag{};

    wallet(create_tag, Monero::NetworkType nettype, std::string filename, std::string password, std::uint64_t kdf_rounds);
    wallet(open_tag, Monero::NetworkType nettpe, std::string filename, std::string password, std::uint64_t kdf_rounds, std::shared_ptr<backend::wallet> data);

    wallet(const wallet&) = delete;
    wallet(wallet&&) = delete;
    virtual ~wallet() override;
    wallet& operator=(const wallet&) = delete;
    wallet& operator=(wallet&&) = delete;

    virtual std::string seed(const std::string& seed_offset = "") const = 0;

    virtual std::string getSeedLanguage() const = 0;
    virtual void setSeedLanguage(const std::string &arg) = 0;

    virtual int status() const override;
    virtual std::string errorString() const override;
    virtual void statusWithErrorString(int& status, std::string& errorString) const override;

    virtual bool setPassword(const std::string &password) override;
    virtual const std::string& getPassword() const override { return password_; }

    virtual bool setDevicePin(const std::string &) override { return false; };
    virtual bool setDevicePassphrase(const std::string &) override { return false; };
    virtual std::string address(uint32_t accountIndex = 0, uint32_t addressIndex = 0) const override;
    virtual std::string path() const = 0;
    virtual Monero::NetworkType nettype() const override;
    //! returns current hard fork info
    virtual void hardForkInfo(uint8_t &version, uint64_t &earliest_height) const = 0;
    //! check if hard fork rules should be used
    virtual bool useForkRules(uint8_t version, int64_t early_blocks) const = 0;  
    /*!
     * \brief integratedAddress - returns integrated address for current wallet address and given payment_id.
     *                            if passed "payment_id" param is an empty string or not-valid payment id string
     *                            (16 characters hexadecimal string) - random payment_id will be generated
     *
     * \param payment_id        - 16 characters hexadecimal string or empty string if new random payment id needs to be
     *                            generated
     * \return                  - 106 characters string representing integrated address
     */
    virtual std::string integratedAddress(const std::string &payment_id) const = 0;
    
   /*!
    * \brief secretViewKey     - returns secret view key
    * \return                  - secret view key
    */
    virtual std::string secretViewKey() const override;

   /*!
    * \brief publicViewKey     - returns public view key
    * \return                  - public view key
    */
    virtual std::string publicViewKey() const override;

   /*!
    * \brief secretSpendKey    - returns secret spend key
    * \return                  - secret spend key
    */
    virtual std::string secretSpendKey() const override;

   /*!
    * \brief publicSpendKey    - returns public spend key
    * \return                  - public spend key
    */
    virtual std::string publicSpendKey() const override;

    /*!
     * \brief publicMultisigSignerKey - returns public signer key
     * \return                        - public multisignature signer key or empty string if wallet is not multisig
     */
    virtual std::string publicMultisigSignerKey() const override
    { throw std::logic_error{"lwsf does not support multisig"}; }

    /*!
     * \brief stop - interrupts wallet refresh() loop once (doesn't stop background refresh thread)
     */
    virtual void stop() override;

    /*!
     * \brief store - stores wallet to file.
     * \param path - main filename to store wallet to. additionally stores address file and keys file.
     *               to store to the same file - just pass empty string;
     * \return
     */
    virtual bool store(const std::string &path) override;
    /*!
     * \brief filename - returns wallet filename
     * \return
     */
    virtual std::string filename() const override { return filename_; }
    /*!
     * \brief keysFilename - returns keys filename. usually this formed as "wallet_filename".keys
     * \return
     */
    virtual std::string keysFilename() const = 0;
    /*!
     * \brief init - initializes wallet with daemon connection params.
     *               if daemon_address is local address, "trusted daemon" will be set to true forcibly
     *               startRefresh() should be called when wallet is initialized.
     *
     * \param daemon_address - daemon address in "hostname:port" format
     * \param daemon_username
     * \param daemon_password
     * \param proxy_address - set proxy address, empty string to disable
     * \return  - true on success
     */
    virtual bool init(const std::string &daemon_address, uint64_t, const std::string &daemon_username = "", const std::string &daemon_password = "", bool use_ssl = false, bool lightWallet = false, const std::string &proxy_address = "") override;

   /*!
    * \brief createWatchOnly - Creates a watch only wallet
    * \param path - where to store the wallet
    * \param password
    * \param language
    * \return  - true if created successfully
    */
    virtual bool createWatchOnly(const std::string &path, const std::string &password, const std::string &language) const = 0;

   /*!
    * \brief setRefreshFromBlockHeight - start refresh from block height on recover
    *
    * \param refresh_from_block_height - blockchain start height
    */
    virtual void setRefreshFromBlockHeight(uint64_t refresh_from_block_height) override;

   /*!
    * \brief getRestoreHeight - get wallet creation height
    *
    */
    virtual uint64_t getRefreshFromBlockHeight() const override;

   /*!
    * \brief setRecoveringFromSeed - set state recover form seed
    *
    * \param recoveringFromSeed - true/false
    */
    virtual void setRecoveringFromSeed(bool recoveringFromSeed) = 0;

   /*!
    * \brief setRecoveringFromDevice - set state to recovering from device
    *
    * \param recoveringFromDevice - true/false
    */
    virtual void setRecoveringFromDevice(bool recoveringFromDevice) = 0;

    /*!
     * \brief setSubaddressLookahead - set size of subaddress lookahead
     *
     * \param major - size fot the major index
     * \param minor - size fot the minor index
     */
    virtual void setSubaddressLookahead(uint32_t major, uint32_t minor) = 0;

    /**
     * @brief connectToDaemon - connects to the daemon. TODO: check if it can be removed
     * @return
     */
    virtual bool connectToDaemon() override;

    /**
     * @brief connected - checks if the wallet connected to the daemon
     * @return - true if connected
     */
    virtual ConnectionStatus connected() const override;
    virtual void setTrustedDaemon(bool) override {} 
    virtual bool trustedDaemon() const override { return true; }
    virtual bool setProxy(const std::string &address) override;
    virtual uint64_t balance(uint32_t accountIndex = 0) const = 0;
    uint64_t balanceAll() const {
        uint64_t result = 0;
        for (uint32_t i = 0; i < numSubaddressAccounts(); ++i)
            result += balance(i);
        return result;
    }
    virtual uint64_t unlockedBalance(uint32_t accountIndex = 0) const = 0;
    uint64_t unlockedBalanceAll() const {
        uint64_t result = 0;
        for (uint32_t i = 0; i < numSubaddressAccounts(); ++i)
            result += unlockedBalance(i);
        return result;
    }

   /**
    * @brief watchOnly - checks if wallet is watch only
    * @return - true if watch only
    */
    virtual bool watchOnly() const = 0;

    /**
     * @brief isDeterministic - checks if wallet keys are deterministic
     * @return - true if deterministic
     */
    virtual bool isDeterministic() const = 0;

    /**
     * @brief blockChainHeight - returns current blockchain height
     * @return
     */
    virtual uint64_t blockChainHeight() const override;

    /**
    * @brief approximateBlockChainHeight - returns approximate blockchain height calculated from date/time
    * @return
    */
    virtual uint64_t approximateBlockChainHeight() const = 0;

    /**
    * @brief estimateBlockChainHeight - returns estimate blockchain height. More accurate than approximateBlockChainHeight,
    *                                   uses daemon height and falls back to calculation from date/time
    * @return
    **/ 
    virtual uint64_t estimateBlockChainHeight() const = 0;
    /**
     * @brief daemonBlockChainHeight - returns daemon blockchain height
     * @return 0 - in case error communicating with the daemon.
     *             status() will return Status_Error and errorString() will return verbose error description
     */
    virtual uint64_t daemonBlockChainHeight() const override;

    /**
     * @brief daemonBlockChainTargetHeight - returns daemon blockchain target height
     * @return 0 - in case error communicating with the daemon.
     *             status() will return Status_Error and errorString() will return verbose error description
     */
    virtual uint64_t daemonBlockChainTargetHeight() const override;

    /**
     * @brief synchronized - checks if wallet was ever synchronized
     * @return
     */
    virtual bool synchronized() const = 0;

    static std::string displayAmount(uint64_t amount);
    static uint64_t amountFromString(const std::string &amount);
    static uint64_t amountFromDouble(double amount);
    static std::string genPaymentId();
    static bool paymentIdValid(const std::string &paiment_id);
    static bool addressValid(const std::string &str, Monero::NetworkType nettype);
    static bool addressValid(const std::string &str, bool testnet)          // deprecated
    {
        return addressValid(str, testnet ? Monero::TESTNET : Monero::MAINNET);
    }
    static bool keyValid(const std::string &secret_key_string, const std::string &address_string, bool isViewKey, Monero::NetworkType nettype, std::string &error);
    static bool keyValid(const std::string &secret_key_string, const std::string &address_string, bool isViewKey, bool testnet, std::string &error)     // deprecated
    {
        return keyValid(secret_key_string, address_string, isViewKey, testnet ? Monero::TESTNET : Monero::MAINNET, error);
    }
    static std::string paymentIdFromAddress(const std::string &str, Monero::NetworkType nettype);
    static std::string paymentIdFromAddress(const std::string &str, bool testnet)       // deprecated
    {
        return paymentIdFromAddress(str, testnet ? Monero::TESTNET : Monero::MAINNET);
    }
    static uint64_t maximumAllowedAmount();
    // Easylogger wrapper
    static void init(const char *argv0, const char *default_log_base_name) { init(argv0, default_log_base_name, "", true); }
    static void init(const char *argv0, const char *default_log_base_name, const std::string &log_path, bool console);
    static void debug(const std::string &category, const std::string &str);
    static void info(const std::string &category, const std::string &str);
    static void warning(const std::string &category, const std::string &str);
    static void error(const std::string &category, const std::string &str);

   /**
    * @brief StartRefresh - Start/resume refresh thread (refresh every 10 seconds)
    */
    virtual void startRefresh() override;
   /**
    * @brief pauseRefresh - pause refresh thread
    */
    virtual void pauseRefresh() override;

    /**
     * @brief refresh - refreshes the wallet, updating transactions from daemon
     * @return - true if refreshed successfully;
     */
    virtual bool refresh() override;

    /**
     * @brief refreshAsync - refreshes wallet asynchronously.
     */
    virtual void refreshAsync() override;

    /**
     * @brief rescanBlockchain - rescans the wallet, updating transactions from daemon
     * @return - true if refreshed successfully;
     */
    virtual bool rescanBlockchain() = 0;

    /**
     * @brief rescanBlockchainAsync - rescans wallet asynchronously, starting from genesys
     */
    virtual void rescanBlockchainAsync() = 0;

    /**
     * @brief setAutoRefreshInterval - setup interval for automatic refresh.
     * @param seconds - interval in millis. if zero or less than zero - automatic refresh disabled;
     */
    virtual void setAutoRefreshInterval(int millis) override;

    /**
     * @brief autoRefreshInterval - returns automatic refresh interval in millis
     * @return
     */
    virtual int autoRefreshInterval() const override;

    /**
     * @brief addSubaddressAccount - appends a new subaddress account at the end of the last major index of existing subaddress accounts
     * @param label - the label for the new account (which is the as the label of the primary address (accountIndex,0))
     */
    virtual void addSubaddressAccount(const std::string& label) = 0;
    /**
     * @brief numSubaddressAccounts - returns the number of existing subaddress accounts
     */
    virtual size_t numSubaddressAccounts() const = 0;
    /**
     * @brief numSubaddresses - returns the number of existing subaddresses associated with the specified subaddress account
     * @param accountIndex - the major index specifying the subaddress account
     */
    virtual size_t numSubaddresses(uint32_t accountIndex) const = 0;
    /**
     * @brief addSubaddress - appends a new subaddress at the end of the last minor index of the specified subaddress account
     * @param accountIndex - the major index specifying the subaddress account
     * @param label - the label for the new subaddress
     */
    virtual void addSubaddress(uint32_t accountIndex, const std::string& label) = 0;
    /**
     * @brief getSubaddressLabel - gets the label of the specified subaddress
     * @param accountIndex - the major index specifying the subaddress account
     * @param addressIndex - the minor index specifying the subaddress
     */
    virtual std::string getSubaddressLabel(uint32_t accountIndex, uint32_t addressIndex) const = 0;
    /**
     * @brief setSubaddressLabel - sets the label of the specified subaddress
     * @param accountIndex - the major index specifying the subaddress account
     * @param addressIndex - the minor index specifying the subaddress
     * @param label - the new label for the specified subaddress
     */
    virtual void setSubaddressLabel(uint32_t accountIndex, uint32_t addressIndex, const std::string &label) = 0;

    /**
     * @brief multisig - returns current state of multisig wallet creation process
     * @return MultisigState struct
     */
    virtual Monero::MultisigState multisig() const = 0;
    /**
     * @brief getMultisigInfo
     * @return serialized and signed multisig info string
     */
    virtual std::string getMultisigInfo() const = 0;
    /**
     * @brief makeMultisig - switches wallet in multisig state. The one and only creation phase for N / N wallets
     * @param info - vector of multisig infos from other participants obtained with getMulitisInfo call
     * @param threshold - number of required signers to make valid transaction. Must be <= number of participants
     * @return in case of N / N wallets returns empty string since no more key exchanges needed. For N - 1 / N wallets returns base58 encoded extra multisig info
     */
    virtual std::string makeMultisig(const std::vector<std::string>& info, uint32_t threshold) = 0;
    /**
     * @brief exchange_multisig_keys - provides additional key exchange round for arbitrary multisig schemes (like N-1/N, M/N)
     * @param info - base58 encoded key derivations returned by makeMultisig or exchangeMultisigKeys function call
     * @param force_update_use_with_caution - force multisig account to update even if not all signers contribute round messages
     * @return new info string if more rounds required or an empty string if wallet creation is done
     */
    virtual std::string exchangeMultisigKeys(const std::vector<std::string> &info, const bool force_update_use_with_caution) = 0;
    /**
     * @brief exportMultisigImages - exports transfers' key images
     * @param images - output paramter for hex encoded array of images
     * @return true if success
     */
    virtual bool exportMultisigImages(std::string& images) = 0;
    /**
     * @brief importMultisigImages - imports other participants' multisig images
     * @param images - array of hex encoded arrays of images obtained with exportMultisigImages
     * @return number of imported images
     */
    virtual size_t importMultisigImages(const std::vector<std::string>& images) = 0;
    /**
     * @brief hasMultisigPartialKeyImages - checks if wallet needs to import multisig key images from other participants
     * @return true if there are partial key images
     */
    virtual bool hasMultisigPartialKeyImages() const = 0;

    /**
     * @brief restoreMultisigTransaction creates PendingTransaction from signData
     * @param signData encrypted unsigned transaction. Obtained with PendingTransaction::multisigSignData
     * @return PendingTransaction
     */
    virtual Monero::PendingTransaction*  restoreMultisigTransaction(const std::string& signData) = 0;

    /*!
     * \brief createTransactionMultDest creates transaction with multiple destinations. if dst_addr is an integrated address, payment_id is ignored
     * \param dst_addr                  vector of destination address as string
     * \param payment_id                optional payment_id, can be empty string
     * \param amount                    vector of amounts
     * \param mixin_count               mixin count. if 0 passed, wallet will use default value
     * \param subaddr_account           subaddress account from which the input funds are taken
     * \param subaddr_indices           set of subaddress indices to use for transfer or sweeping. if set empty, all are chosen when sweeping, and one or more are automatically chosen when transferring. after execution, returns the set of actually used indices
     * \param priority
     * \return                          PendingTransaction object. caller is responsible to check PendingTransaction::status()
     *                                  after object returned
     */

    virtual Monero::PendingTransaction* createTransactionMultDest(const std::vector<std::string> &dst_addr, const std::string &payment_id,
                                                   Monero::optional<std::vector<uint64_t>> amount, uint32_t mixin_count,
                                                   Monero::PendingTransaction::Priority = Monero::PendingTransaction::Priority_Low,
                                                   uint32_t subaddr_account = 0,
                                                   std::set<uint32_t> subaddr_indices = {}) = 0;

    /*!
     * \brief createTransaction creates transaction. if dst_addr is an integrated address, payment_id is ignored
     * \param dst_addr          destination address as string
     * \param payment_id        optional payment_id, can be empty string
     * \param amount            amount
     * \param mixin_count       mixin count. if 0 passed, wallet will use default value
     * \param subaddr_account   subaddress account from which the input funds are taken
     * \param subaddr_indices   set of subaddress indices to use for transfer or sweeping. if set empty, all are chosen when sweeping, and one or more are automatically chosen when transferring. after execution, returns the set of actually used indices
     * \param priority
     * \return                  PendingTransaction object. caller is responsible to check PendingTransaction::status()
     *                          after object returned
     */

    virtual Monero::PendingTransaction* createTransaction(const std::string &dst_addr, const std::string &payment_id,
                                                   std::optional<uint64_t> amount, uint32_t mixin_count,
                                                   Monero::PendingTransaction::Priority = Monero::PendingTransaction::Priority_Low,
                                                   uint32_t subaddr_account = 0,
                                                   std::set<uint32_t> subaddr_indices = {}) = 0;

    /*!
     * \brief createSweepUnmixableTransaction creates transaction with unmixable outputs.
     * \return                  PendingTransaction object. caller is responsible to check PendingTransaction::status()
     *                          after object returned
     */

    virtual Monero::PendingTransaction* createSweepUnmixableTransaction() = 0;
    
   /*!
    * \brief loadUnsignedTx  - creates transaction from unsigned tx file
    * \return                - UnsignedTransaction object. caller is responsible to check UnsignedTransaction::status()
    *                          after object returned
    */
    virtual Monero::UnsignedTransaction* loadUnsignedTx(const std::string &unsigned_filename) = 0;
    
   /*!
    * \brief submitTransaction - submits transaction in signed tx file
    * \return                  - true on success
    */
    virtual bool submitTransaction(const std::string &fileName) = 0;
    

    /*!
     * \brief disposeTransaction - destroys transaction object
     * \param t -  pointer to the "PendingTransaction" object. Pointer is not valid after function returned;
     */
    virtual void disposeTransaction(Monero::PendingTransaction * t) override final
    {}

    /*!
     * \brief Estimates transaction fee.
     * \param destinations Vector consisting of <address, amount> pairs.
     * \return Estimated fee.
     */
    virtual uint64_t estimateTransactionFee(const std::vector<std::pair<std::string, uint64_t>> &destinations,
                                            Monero::PendingTransaction::Priority priority) const override final;

   /*!
    * \brief exportKeyImages - exports key images to file
    * \param filename
    * \param all - export all key images or only those that have not yet been exported
    * \return                  - true on success
    */
    virtual bool exportKeyImages(const std::string &filename, bool all = false) override;
   
   /*!
    * \brief importKeyImages - imports key images from file
    * \param filename
    * \return                  - true on success
    */
    virtual bool importKeyImages(const std::string &filename) override;

    /*!
     * \brief importOutputs - exports outputs to file
     * \param filename
     * \return                  - true on success
     */
    virtual bool exportOutputs(const std::string &filename, bool all = false) override;

    /*!
     * \brief importOutputs - imports outputs from file
     * \param filename
     * \return                  - true on success
     */
    virtual bool importOutputs(const std::string &filename) override;

    /*!
     * \brief scanTransactions - scan a list of transaction ids, this operation may reveal the txids to the remote node and affect your privacy
     * \param txids            - list of transaction ids
     * \return                 - true on success
     */
    virtual bool scanTransactions(const std::vector<std::string> &txids) override;

    virtual Monero::TransactionHistory* history() override;
    virtual Monero::AddressBook* addressBook() override;
    virtual Monero::Subaddress* subaddress() = 0;
    virtual Monero::SubaddressAccount* subaddressAccount() override;
    virtual void setListener(Monero::WalletListener*) override;
    /*!
     * \brief defaultMixin - returns number of mixins used in transactions
     * \return
     */
    virtual uint32_t defaultMixin() const override;
    /*!
     * \brief setDefaultMixin - setum number of mixins to be used for new transactions
     * \param arg
     */
    virtual void setDefaultMixin(uint32_t arg) override;

    /*!
     * \brief setCacheAttribute - attach an arbitrary string to a wallet cache attribute
     * \param key - the key
     * \param val - the value
     * \return true if successful, false otherwise
     */
    virtual bool setCacheAttribute(const std::string &key, const std::string &val) override;
    /*!
     * \brief getCacheAttribute - return an arbitrary string attached to a wallet cache attribute
     * \param key - the key
     * \return the attached string, or empty string if there is none
     */
    virtual std::string getCacheAttribute(const std::string &key) const = 0;
    /*!
     * \brief setUserNote - attach an arbitrary string note to a txid
     * \param txid - the transaction id to attach the note to
     * \param note - the note
     * \return true if successful, false otherwise
     */
    virtual bool setUserNote(const std::string &txid, const std::string &note) override;
    /*!
     * \brief getUserNote - return an arbitrary string note attached to a txid
     * \param txid - the transaction id to attach the note to
     * \return the attached note, or empty string if there is none
     */
    virtual std::string getUserNote(const std::string &txid) const override;
    virtual std::string getTxKey(const std::string &txid) const override;
    virtual bool checkTxKey(const std::string &txid, std::string tx_key, const std::string &address, uint64_t &received, bool &in_pool, uint64_t &confirmations) = 0;
    virtual std::string getTxProof(const std::string &txid, const std::string &address, const std::string &message) const = 0;
    virtual bool checkTxProof(const std::string &txid, const std::string &address, const std::string &message, const std::string &signature, bool &good, uint64_t &received, bool &in_pool, uint64_t &confirmations) = 0;
    virtual std::string getSpendProof(const std::string &txid, const std::string &message) const = 0;
    virtual bool checkSpendProof(const std::string &txid, const std::string &message, const std::string &signature, bool &good) const = 0;
    /*!
     * \brief getReserveProof - Generates a proof that proves the reserve of unspent funds
     *                          Parameters `account_index` and `amount` are ignored when `all` is true
     */
    virtual std::string getReserveProof(bool all, uint32_t account_index, uint64_t amount, const std::string &message) const = 0;
    virtual bool checkReserveProof(const std::string &address, const std::string &message, const std::string &signature, bool &good, uint64_t &total, uint64_t &spent) const = 0;

    /*
     * \brief signMessage - sign a message with the spend private key
     * \param message - the message to sign (arbitrary byte data)
     * \return the signature
     */
    virtual std::string signMessage(const std::string &message, const std::string &address = "") = 0;
    /*!
     * \brief verifySignedMessage - verify a signature matches a given message
     * \param message - the message (arbitrary byte data)
     * \param address - the address the signature claims to be made with
     * \param signature - the signature
     * \return true if the signature verified, false otherwise
     */
    virtual bool verifySignedMessage(const std::string &message, const std::string &addres, const std::string &signature) const = 0;

    /*!
     * \brief signMultisigParticipant   signs given message with the multisig public signer key
     * \param message                   message to sign
     * \return                          signature in case of success. Sets status to Error and return empty string in case of error
     */
    virtual std::string signMultisigParticipant(const std::string &message) const = 0;
    /*!
     * \brief verifyMessageWithPublicKey verifies that message was signed with the given public key
     * \param message                    message
     * \param publicKey                  hex encoded public key
     * \param signature                  signature of the message
     * \return                           true if the signature is correct. false and sets error state in case of error
     */
    virtual bool verifyMessageWithPublicKey(const std::string &message, const std::string &publicKey, const std::string &signature) const = 0;

    virtual bool parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error) = 0;
    virtual std::string make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const = 0;

    virtual std::string getDefaultDataDir() const = 0;
   
   /*
    * \brief rescanSpent - Rescan spent outputs - Can only be used with trusted daemon
    * \return true on success
    */
    virtual bool rescanSpent() = 0;

   /*
    * \brief setOffline - toggle set offline on/off
    * \param offline - true/false
    */
    virtual void setOffline(bool offline) = 0;
    virtual bool isOffline() const = 0;
    
    //! blackballs a set of outputs
    virtual bool blackballOutputs(const std::vector<std::string> &outputs, bool add) = 0;

    //! blackballs an output
    virtual bool blackballOutput(const std::string &amount, const std::string &offset) = 0;

    //! unblackballs an output
    virtual bool unblackballOutput(const std::string &amount, const std::string &offset) = 0;

    //! gets the ring used for a key image, if any
    virtual bool getRing(const std::string &key_image, std::vector<uint64_t> &ring) const = 0;

    //! gets the rings used for a txid, if any
    virtual bool getRings(const std::string &txid, std::vector<std::pair<std::string, std::vector<uint64_t>>> &rings) const = 0;

    //! sets the ring used for a key image
    virtual bool setRing(const std::string &key_image, const std::vector<uint64_t> &ring, bool relative) = 0;

    //! sets whether pre-fork outs are to be segregated
    virtual void segregatePreForkOutputs(bool segregate) = 0;

    //! sets the height where segregation should occur
    virtual void segregationHeight(uint64_t height) = 0;

    //! secondary key reuse mitigation
    virtual void keyReuseMitigation2(bool mitigation) = 0;

    //! locks/unlocks the keys file; returns true on success
    virtual bool lockKeysFile() = 0;
    virtual bool unlockKeysFile() = 0;
    //! returns true if the keys file is locked
    virtual bool isKeysFileLocked() = 0;

    /*!
     * \brief Queries backing device for wallet keys
     * \return Device they are on
     */
    virtual Device getDeviceType() const = 0;

    //! cold-device protocol key image sync
    virtual uint64_t coldKeyImageSync(uint64_t &spent, uint64_t &unspent) = 0;

    //! shows address on device display
    virtual void deviceShowAddress(uint32_t accountIndex, uint32_t addressIndex, const std::string &paymentId) = 0;

    //! attempt to reconnect to hardware device
    virtual bool reconnectDevice() = 0;

    //! get bytes received
    virtual uint64_t getBytesReceived() = 0;

    //! get bytes sent
    virtual uint64_t getBytesSent() = 0;
  };
}} // lwsf // internal
