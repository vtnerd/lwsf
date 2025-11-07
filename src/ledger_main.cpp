// Copyright (c) 2025, The Monero Project
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

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <ctime>
#include <iostream>
#include <filesystem>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>

#include "common/command_line.h" // monero/src
#include "common/expect.h"       // monero/src
#include "common/password.h"     // monero/src
#include "common/util.h"         // monero/src
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "error.h"

namespace
{
  enum class backend_type : unsigned char { lws = 0, monerod };
  struct options
  {
    const command_line::arg_descriptor<std::string> wallet_file;
    const command_line::arg_descriptor<std::string> lws_url;
    const command_line::arg_descriptor<std::string> network;
    const command_line::arg_descriptor<std::string> backend;
    const command_line::arg_descriptor<std::string> config_file;

    options()
      : wallet_file{"wallet-file", "Path to read-and-store wallet. Omit to skip wallet cache storage."}
      , lws_url{"lws-url", "<protocol>://address:port of LWS server REST API (or monerod if using that backend). Omit to read cached data."}
      , network{"network", "<\"main\"|\"stage\"|\"test\"> - Blockchain net type", "main"}
      , backend{"backend", "<\"lws\"|\"monerod\"> - Backend used for file cache and probing", "lws"}
      , config_file{"config-file", "Specify any option in a config file; <name>=<value> on separate lines"}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      command_line::add_arg(description, wallet_file);
      command_line::add_arg(description, lws_url);
      command_line::add_arg(description, config_file);
      command_line::add_arg(description, network);
      command_line::add_arg(description, backend);
      command_line::add_arg(description, command_line::arg_help);
    }

    Monero::NetworkType get_network(boost::program_options::variables_map const& args) const
    {
      const std::string net = command_line::get_arg(args, network);
      if (net == "main")
        return Monero::MAINNET;
      else if (net == "stage")
        return Monero::STAGENET;
      else if (net == "test")
        return Monero::TESTNET;
      else
        throw std::runtime_error{"Bad --network value"};
    }

    backend_type get_backend(boost::program_options::variables_map const& args) const
    {
      const std::string type = command_line::get_arg(args, backend);
      if (type == "lws")
        return backend_type::lws;
      else if (type == "monerod")
        return backend_type::monerod;
      else
        throw std::runtime_error{"Bad --backend value"};
    }
  };

  struct program
  {
    std::string wallet_file;
    std::string lws_url;
    Monero::NetworkType network;
    backend_type backend;
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options]" << std::endl;
    out << description;
  }

  std::optional<program> get_program(int argc, char** argv)
  {
    namespace po = boost::program_options;

    const options opts{};
    po::variables_map args{};
    {
      po::options_description description{"Options"};
      opts.prepare(description);

      po::store(
        po::command_line_parser(argc, argv).options(description).run(), args
      );
      po::notify(args);

      if (!command_line::is_arg_defaulted(args, opts.config_file))
      {
        std::filesystem::path config_path{command_line::get_arg(args, opts.config_file)};
        if (!std::filesystem::exists(config_path))
          MONERO_THROW(lwsf::error::configuration, "Config file does not exist");

        po::store(
          po::parse_config_file<char>(config_path.string().c_str(), description), args
        );
        po::notify(args);
      }
    }

    if (command_line::get_arg(args, command_line::arg_help))
    {
      print_help(std::cout);
      return std::nullopt;
    }

    program prog{
      command_line::get_arg(args, opts.wallet_file),
      command_line::get_arg(args, opts.lws_url),
      opts.get_network(args),
      opts.get_backend(args)
    };

    return prog;
  }

  void run(program prog)
  {
    std::unique_ptr<Monero::WalletManager> wm;
    switch (prog.backend)
    {
    default:
    case backend_type::lws:
      wm.reset(lwsf::WalletManagerFactory::getWalletManager());
      break;
    case backend_type::monerod:
      wm.reset(Monero::WalletManagerFactory::getWalletManager());
      break;
    };
    if (!wm)
      throw std::runtime_error{"Unexpected WalletManager nullptr"};

    std::unique_ptr<Monero::Wallet> wallet;  
    {
      if (prog.wallet_file.empty() || !wm->walletExists(prog.wallet_file))
      {
        std::cout << "Input seed words: ";
        std::string seed;
        std::getline(std::cin, seed, '\n');

        std::string pass;
        if (!prog.wallet_file.empty())
        {
          const auto wiped = tools::password_container::prompt(true, "Wallet File Password");
          if (!wiped)
            throw std::runtime_error{"Failed to get password"};
          pass.assign(wiped->password().data(), wiped->password().size());
        }

        wallet.reset(wm->recoveryWallet(prog.wallet_file, pass, seed, prog.network));
      }
      else
      {
        const auto wiped = tools::password_container::prompt(false, "Wallet File Password");
        if (!wiped)
          throw std::runtime_error{"Failed to get password"};

        const std::string pass{wiped->password().data(), wiped->password().size()};
        wallet.reset(wm->openWallet(prog.wallet_file, pass, prog.network));

        int status = 0;
        std::string error;
        wallet->statusWithErrorString(status, error);
        if (status != Monero::Wallet::Status_Ok)
          throw std::runtime_error{"Failed to open wallet: " + error};
      }

      if (!wallet)
        throw std::runtime_error{"Unexpected Wallet nullptr"};
    }

    if (!prog.lws_url.empty())
    {
      wallet->setAutoRefreshInterval(0); // do not start background thread
      if (!wallet->init(prog.lws_url, 0, "", "", (prog.lws_url.substr(0, 8) == "https://"), true) || !wallet->refresh())
        throw std::runtime_error{"Failed to refresh wallet: " + wallet->errorString()};
    }

    if (!prog.wallet_file.empty())
    {
      if (!wallet->store({}))
        throw std::runtime_error{"Failed to store wallet file: " + wallet->errorString()};
    }

    std::cout << "; Primary Address: " << wallet->address() << std::endl;
    std::cout << "; Blockchain Height: " << wallet->daemonBlockChainHeight() << std::endl;
    std::cout << "; Start Height: " << wallet->getRefreshFromBlockHeight() << std::endl;
    std::cout << "; Scan Height: " << wallet->blockChainHeight() << std::endl;
    std::cout << "; Accounts: " << wallet->numSubaddressAccounts() << std::endl;

    Monero::TransactionHistory* history = wallet->history();
    if (!history)
      throw std::runtime_error{"Unexpected history nullptr"};

    history->refresh();
    const std::vector<Monero::TransactionInfo*>& info_list = history->getAll();

    std::cout << "; Transactions: " << info_list.size() << std::endl << std::endl;

    std::multimap<std::uint64_t, const Monero::TransactionInfo*> ordered;
    for (const Monero::TransactionInfo* info : info_list)
    {
      if (info)
        ordered.emplace(info->blockHeight(), info);
    }

    for (const auto elem : ordered)
    {
      auto info = elem.second;
      std::tm expanded{};
      const std::time_t timestamp = info->timestamp();
      if (!gmtime_r(std::addressof(timestamp), std::addressof(expanded)))
        throw std::runtime_error{"gmtime failure"};

      char buf[11] = {0};
      if (sizeof(buf) - 1 != std::strftime(buf, sizeof(buf), "%Y/%m/%d", std::addressof(expanded)))
        throw std::runtime_error{"strftime failed"};

      std::cout << buf << " (" << info->hash() << ") " << info->description() << std::endl;

      const std::string& label = info->label();
      const std::string& account = label.empty() ? std::to_string(info->subaddrAccount()) : label;
      if (info->direction() == Monero::TransactionInfo::Direction_In)
      { 
        std::cout << "    Assets:Monero:" << account << "      " << cryptonote::print_money(info->amount()) << " XMR" << std::endl;
        std::cout << "    Income" << std::endl;
      }
      else
      {
        std::cout << "    Expenses             " << cryptonote::print_money(info->amount()) << " XMR " << std::endl;
        std::cout << "    Expenses:Monero:Fee  " << cryptonote::print_money(info->fee()) << " XMR" << std::endl;
        std::cout << "    Assets:Monero:" << account << std::endl;
      }
    }
  }
}

int main(int argc, char** argv)
{
  try
  {
    std::optional<program> prog;

    try
    {
      prog = get_program(argc, argv);
    }
    catch (std::exception const& e)
    {
      std::cerr << e.what() << std::endl << std::endl;
      print_help(std::cerr);
      return EXIT_FAILURE;
    }

    if (prog)
      run(std::move(*prog));
  }
  catch (std::exception const& e)
  {
    std::cerr << e.what() << std::endl;;
    return EXIT_FAILURE;
  }
  catch (...)
  {
    std::cerr << "Unknown exception" << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

