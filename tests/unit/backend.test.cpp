// Copyright (c) 2025, The Monero Project
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

#include "framework.test.h"
#include "backend.h"

#include <array>
#include <atomic>
#include <boost/asio/coroutine.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/beast/websocket/error.hpp>
#include <boost/optional/optional.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/utility/string_view.hpp>
#include <boost/variant/variant.hpp>
#include <deque>
#include <functional>
#include <ostream>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#include "hex.h"                    // monero/contrib/include
#include "rapidjson/document.h"     // monero/external/rapidjson/include
#include "rapidjson/error/en.h"     // monero/external/rapidjson/include
#include "rapidjson/stringbuffer.h" // monero/external/rapidjson/incldue
#include "rapidjson/writer.h"       // monero/external/rapidjson/incldue
#include "ringct/rctOps.h"          // monero/src
#include "net/http.h"
#include "net/websocket.h"
#include "net/push.test.h"
#include "wire/adapted/crypto.h"
#include "wire/msgpack.h"

namespace rapidjson
{
  std::ostream& operator<<(std::ostream& out, const Document& src)
  {
    StringBuffer buffer;
    Writer<StringBuffer> writer{buffer};
    src.Accept(writer);
    
    return out << buffer.GetString();
  }
}

namespace
{
  using client_request =
    boost::beast::http::request<boost::beast::http::string_body>;

  template<typename T>
  std::string to_hex(const T& arg)
  {
    return epee::to_hex::string(epee::as_byte_span(arg));
  }

  template<typename T>
  T from_hex(const boost::string_ref hex)
  {
    T out{};
    if (!epee::from_hex::to_buffer(epee::as_mut_byte_span(out), hex))
      throw std::runtime_error{"invalid hex"};
    return out;
  }

  void to_msgpack(lwsf::wire::msgpack_writer& dest, const rapidjson::Value& src)
  {
    switch (src.GetType())
    {
      default:
      case rapidjson::kNullType:
        throw std::logic_error{"unexpected json value - " + std::to_string(src.GetType())};
      case rapidjson::kFalseType:
        dest.boolean(false);
        break;
      case rapidjson::kTrueType:
        dest.boolean(true);
        break;
      case rapidjson::kObjectType:
        dest.start_object(src.MemberCount());
        {
          const auto end = src.MemberEnd();
          for (auto cur = src.MemberBegin(); cur != end; ++cur)
          {
            dest.key({cur->name.GetString(), cur->name.GetStringLength()});
            to_msgpack(dest, cur->value);
          }
        }
        dest.end_object();
        break;
      case rapidjson::kArrayType:
        dest.start_array(src.Size());
        {
          for (std::size_t i = 0; i < src.Size(); ++i)
            to_msgpack(dest, src[i]);
        }
        dest.end_array();
        break;
      case rapidjson::kStringType:
        {
          std::string binary;
          const boost::string_ref str{src.GetString(), src.GetStringLength()};
          if (epee::from_hex::to_string(binary, str))
            dest.binary(epee::to_byte_span(epee::to_span(binary)));
          else
            dest.string(str);
        }
        break;
      case rapidjson::kNumberType:
        if (src.IsUint()) dest.unsigned_integer(src.GetUint());
        else if (src.IsUint64()) dest.unsigned_integer(std::uintmax_t(src.GetUint64()));
        else if (src.IsInt()) dest.integer(src.GetInt());
        else if (src.IsInt64()) dest.integer(std::intmax_t(src.GetInt64()));
        else throw std::logic_error{"unexpected json number"};
        break;
    }
  }

  std::string to_msgpack(const std::string& src)
  {
    rapidjson::Document ir;
    ir.Parse(src.c_str());
    if (ir.HasParseError())
      throw std::runtime_error{GetParseError_En(ir.GetParseError())};

    lwsf::wire::msgpack_slice_writer dest{};
    to_msgpack(dest, ir);

    const auto bytes = dest.take_sink();
    return std::string{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
  }

  struct empty_slice
  {
    operator epee::byte_slice() const { return {}; }
  };

  struct empty_decoys
  {
    operator lwsf::internal::rpc::get_random_outs_request() const { return {}; }
  };

  struct login
  {
    struct details
    {
      std::string address;
      crypto::secret_key view_key;
    };

    details account;
  };

  void read_bytes(lwsf::wire::reader& src, login::details& self)
  {
    lwsf::wire::object(src, LWSF_WIRE_FIELD(address), LWSF_WIRE_FIELD(view_key));
  }

  void read_bytes(lwsf::wire::reader& src, login& self)
  {
    lwsf::wire::object(src, LWSF_WIRE_FIELD(account));
  }

  struct response_loop : boost::asio::coroutine
  {
    struct frame
    {
      lest::env& lest_env;
      lwsf_test::net::push::socket server;
      boost::beast::flat_buffer buffer;
      boost::optional<client_request> request;
      boost::beast::http::response<boost::beast::http::string_body> response;
      std::deque<std::pair<std::string, std::string>> requests;
      std::deque<boost::variant<std::string, boost::beast::http::status>> responses;
      std::shared_ptr<lwsf_test::net::push::connection> ws;

      explicit frame(lest::env& lest_env, boost::asio::io_context& io)
        : lest_env(lest_env), server(io), buffer(), request(), response(), requests(), responses(), ws()
      {}

      ~frame()
      {
        if (ws)
          lwsf_test::net::push::async_close(std::move(ws));
      }
    };

    std::shared_ptr<frame> self;

    explicit response_loop(std::shared_ptr<frame> in)
      : boost::asio::coroutine(), self(in)
    {}

    void operator()(boost::system::error_code = {}, std::size_t = {})
    {
      auto& lest_env = self->lest_env;
      LWSF_VERIFY(self);
      BOOST_ASIO_CORO_REENTER(*this)
      {
        while (!self->responses.empty())
        {
          self->request.emplace();
          BOOST_ASIO_CORO_YIELD boost::beast::http::async_read(self->server, self->buffer, *self->request, *this);

          EXPECT(self->request->keep_alive());
          EXPECT(self->requests.size() == self->responses.size());
          EXPECT(self->requests.front().first == self->request->target());
          if (!self->requests.front().second.empty())
          {
            rapidjson::Document expected;
            expected.Parse(self->requests.front().second.c_str());
            EXPECT(!expected.HasParseError());

            rapidjson::Document actual;
            actual.Parse(self->request->body().c_str());
            EXPECT(!expected.HasParseError());

            EXPECT(expected == actual);
          }
          self->requests.pop_front();

          {
            LWSF_VERIFY(!self->responses.empty());
            boost::variant<std::string, boost::beast::http::status> response;
            response.swap(self->responses.front());
            self->responses.pop_front();
            {
              const auto string = boost::get<std::string>(std::addressof(response));
              if (!string)
              {
                const auto status = boost::get<boost::beast::http::status>(response);
                if (status == boost::beast::http::status::switching_protocols)
                {
                  auto self_ = self;
                  lwsf_test::net::push::async_handshake(std::move(self->server), *self->request, [self_] (auto ws) {
                    self_->ws = ws.value();
                  });
                  return;
                }
                else
                  self->response = {status, 11, std::string{}};
              }
              else
                self->response = {boost::beast::http::status::ok, 11, *string};
            }
          }
          self->response.keep_alive(true);
          self->response.prepare_payload();
 
          BOOST_ASIO_CORO_YIELD boost::beast::http::async_write(self->server, self->response, *this);
        }
      }
    }
  };

  std::string get_response(const boost::string_view target)
  {
    static constexpr const char get_address_txs[] =
      R"({
        "total_received": "5000",
        "scanned_height": 150,
        "scanned_block_height": 150,
        "start_height": 10,
        "blockchain_height": 200,
        "transactions": []
      })";

    static constexpr const char get_unspent_outs[] =
      R"({"per_byte_fee": 5, "fee_mask": 100, "amount": "200", "outputs": []})";
    static constexpr const char import_wallet_request[] =
      R"({"lookahead": {"maj_i": 50, "min_i": 200}, "status": "OK", "new_request": true, "request_fulfilled": true})";

    static constexpr const std::array<std::pair<boost::string_view, boost::string_view>, 10> endpoints =
    {{
      {"/get_address_txs",       get_address_txs},
      {"/get_random_outs",       R"({"amount_outs": []})"},
      {"/get_subaddrs",          R"({"all_subaddrs": []})"},
      {"/get_unspent_outs",      get_unspent_outs},
      {"/get_version",           R"({"max_subaddresses": 10000})"},
      {"/import_wallet_request", import_wallet_request},
      {"/login",                 R"({"new_address": true})"},
      {"/provision_subaddrs",    R"({"new_subaddrs": [], "all_subaddrs": []})"},
      {"/submit_raw_tx",         R"({"status": "OK"})"},
      {"/upsert_subaddrs",       "{}"}
    }};

    const auto found =
      std::lower_bound(endpoints.begin(), endpoints.end(), std::make_pair(target, boost::string_view{}));
    if (found != endpoints.end() && found->first == target)
      return std::string{found->second};

    throw std::runtime_error{"Unexpected target: " + std::string{target}};
  }

  struct dummy_server : boost::asio::coroutine
  {
    struct frame
    {
      boost::asio::ip::tcp::socket server;
      boost::beast::flat_buffer buffer;
      boost::optional<client_request> request;
      boost::beast::http::response<boost::beast::http::string_body> response;
      std::mt19937 eng;
      std::uniform_int_distribution<unsigned> dist;

      explicit frame(boost::asio::io_context& io)
        : server(io), buffer(), request(), response(), eng(crypto::rand<std::uint32_t>()), dist(0, 99)
      {}
    };

    std::shared_ptr<frame> self;

    explicit dummy_server(std::shared_ptr<frame> self)
      : boost::asio::coroutine(), self(std::move(self))
    {}

    void operator()(const boost::system::error_code error, std::size_t = {})
    {
      if (error)
      {
        if (error != boost::asio::error::operation_aborted)
          throw boost::system::system_error{error, "server failure"};
        return;
      }

      LWSF_VERIFY(self);
      BOOST_ASIO_CORO_REENTER(*this)
      {
        while (true)
        {
          self->request.emplace();
          BOOST_ASIO_CORO_YIELD boost::beast::http::async_read(self->server, self->buffer, *self->request, *this);

          LWSF_VERIFY(self->request->keep_alive());
          if (self->request->target() == "/feed")
            self->response = {boost::beast::http::status::not_found, 11, ""};
          else if (self->dist(self->eng))
            self->response = {boost::beast::http::status::ok, 11, get_response(self->request->target())};
          else
            self->response = {boost::beast::http::status::internal_server_error, 11, ""};
          self->response.keep_alive(true);
          self->response.prepare_payload();

          BOOST_ASIO_CORO_YIELD boost::beast::http::async_write(self->server, self->response, *this);
        } 
      }
    }
  };
}

LWS_CASE("backend::account")
{
  using subaddrs = lwsf::internal::rpc::subaddrs;

  SETUP("empty with zero lookahead")
  {
    lwsf::internal::backend::account account{.lookahead = {}};
    account.subaccounts.emplace_back().detail.try_emplace(0);

    boost::container::flat_map<std::uint32_t, subaddrs> majors{};
    EXPECT(account.needed_subaddresses(majors) == 0);

    SECTION("standard lookahead")
    {
      account.lookahead = {50, 200};
      EXPECT(account.needed_subaddresses(majors) == 10000);

      account.subaccounts.back().last = 10;
      EXPECT(account.needed_subaddresses(majors) == 10010);

      account.subaccounts.emplace_back().last = 10;
      EXPECT(account.needed_subaddresses(majors) == 10220);
    }

    SECTION("standard lookahead with overlapping custom lookaheads")
    {
      account.lookahead = {50, 200};
      majors.try_emplace(0, subaddrs{}).first->second.value = {{10, 20}, {50, 155}};

      EXPECT(account.needed_subaddresses(majors) == 10000);
    }

    SECTION("standard lookahead with non-overlapping custom lookaheads")
    {
      account.lookahead = {50, 200};
      majors.try_emplace(0, subaddrs{}).first->second.value = {{199, 201}};
      majors.try_emplace(50, subaddrs{}).first->second.value = {{199, 201}};

      EXPECT(account.needed_subaddresses(majors) == 10005);
    }
  }
}

LWS_CASE("backend::wallet (non-websocket)")
{
  using bwallet = lwsf::internal::backend::wallet;
  using tcp = boost::asio::ip::tcp;
  const auto no_ssl = epee::net_utils::ssl_support_t::e_ssl_support_disabled;

  SETUP("base empty wallet and basic server")
  {
    boost::asio::io_context io;
    const auto wallet = std::make_shared<lwsf::internal::backend::wallet>(io);
    crypto::generate_keys(wallet->primary.view.pub, wallet->primary.view.sec);
    crypto::generate_keys(wallet->primary.spend.pub, wallet->primary.spend.sec);
    wallet->primary.address = wallet->get_spend_address({0, 0});

    tcp::acceptor acceptor{io, tcp::endpoint(tcp::v4(), 0)};
    acceptor.listen();

    SECTION("uninitialized http client")
    {
      using namespace std::placeholders;
      const std::array<std::pair<std::function<void(std::function<void(std::error_code)>)>, std::string>, 6> funcs1
      {{
        {std::bind(bwallet::refresh, wallet, true, _1), "refresh"},
        {std::bind(bwallet::get_fees, wallet, _1), "get_fees"},
        {std::bind(bwallet::register_subaccount, wallet, 0, _1), "register_subaccount"},
        {std::bind(bwallet::register_subaddress, wallet, 0, 0, _1), "register_subaddress"},
        {std::bind(bwallet::set_lookahead, wallet, 0, 0, _1), "set_lookahead"},
        {std::bind(bwallet::send_tx, wallet, empty_slice{}, _1), "send_tx"}
      }};

      for (const auto& func : funcs1)
      {
        const lest::ctx ctx{lest_env, func.second};

        std::error_code actual{};
        func.first([&] (auto result) { actual = result; });

        io.restart();
        io.run();

        EXPECT(actual == common_error::kInvalidArgument);
      }

      std::error_code actual = {};
      const auto func = [&](auto result) { actual = result.error(); };
    
      bwallet::login_is_new(wallet, func);
      io.restart();
      io.run();
      EXPECT(actual == common_error::kInvalidArgument);

      bwallet::restore_height_raw(wallet, 0, func);
      io.restart();
      io.run();
      EXPECT(actual == common_error::kInvalidArgument);

      actual = {};
      bwallet::get_decoys(wallet, lwsf::internal::rpc::get_random_outs_request{}, func);
      io.restart();
      io.run();
      EXPECT(actual == common_error::kInvalidArgument);
    }

    SECTION("login_is_new")
    {
      const auto frame = std::make_shared<response_loop::frame>(lest_env, io);
      wallet->client.init(io, "127.0.0.1", "", acceptor.local_endpoint().port(), no_ssl);
 
      bool done = false;
      expect<bool> result = false;
      const auto record_response = [&] (expect<bool> val) { done = true; result = val; };
      bwallet::login_is_new(wallet, record_response);

      wallet->passed_login = false;
      acceptor.async_accept(frame->server, response_loop{frame});

      SECTION("new address -> true")
      {
        frame->requests = {{"/login", ""}, {"/upsert_subaddrs", ""}};
        frame->responses = {R"({"new_address": true})", ""}; 

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        EXPECT(frame->responses.size() == 0);
        EXPECT(result);
        EXPECT(*result);
        EXPECT(wallet->passed_login);
        EXPECT(wallet->primary.restore_height == 0);
        EXPECT(wallet->server_lookahead.major == 0);
        EXPECT(wallet->server_lookahead.minor == 0);
      }

      SECTION("new address -> true with queued")
      {
        frame->requests = {{"/login", ""}, {"/upsert_subaddrs", ""}};
        frame->responses = {R"({"new_address": true})", ""}; 

        bool done2 = true;
        expect<bool> result2 = false;
        bwallet::login_is_new(wallet, [&](auto val) { done2 = true; result2 = val; });
        while (!done || !done2)
        {
          io.restart();
          io.run_one();
        }

        EXPECT(frame->responses.size() == 0);
        EXPECT(result);
        EXPECT(*result);
        EXPECT(result2);
        EXPECT(*result2);
        EXPECT(wallet->passed_login);
        EXPECT(wallet->primary.restore_height == 0);
        EXPECT(wallet->server_lookahead.major == 0);
        EXPECT(wallet->server_lookahead.minor == 0);
      }

      SECTION("new address -> false + start_height")
      {
        frame->requests = {{"/login", ""}, {"/upsert_subaddrs", ""}};
        frame->responses = {R"({"new_address": false, "start_height": 100})", ""};

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        EXPECT(frame->responses.size() == 0);
        EXPECT(result);
        EXPECT(!*result);
        EXPECT(wallet->passed_login);
        EXPECT(wallet->primary.restore_height == 100);
        EXPECT(wallet->server_lookahead.major == 0);
        EXPECT(wallet->server_lookahead.minor == 0);

        wallet->primary.restore_height = 0;
      }

      SECTION("new address -> true with lookahead")
      {
        frame->requests = {{"/login", ""}};
        frame->responses = {
          R"({"new_address": true, "lookahead": {"maj_i": 100, "min_i": 50}})"
        };

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        EXPECT(frame->responses.size() == 0);
        EXPECT(result);
        EXPECT(*result);
        EXPECT(wallet->passed_login);
        EXPECT(wallet->primary.restore_height == 0);
        EXPECT(wallet->server_lookahead.major == 100);
        EXPECT(wallet->server_lookahead.minor == 50);
      }

      SECTION("address is disabled")
      {
        frame->requests = {{"/login", ""}};
        frame->responses = {boost::beast::http::status::forbidden};

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        EXPECT(frame->responses.size() == 0);
        EXPECT(result == lwsf::error::approval);
        EXPECT(!wallet->passed_login);

      }

      SECTION("404 (bad server entirely)")
      {
        frame->requests = {{"/login", ""}, {"/login", ""}};
        frame->responses = {
          boost::beast::http::status::not_found,
          boost::beast::http::status::not_found
        };

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        EXPECT(frame->responses.size() == 0);
        EXPECT(!result);
        EXPECT(result == lwsf::internal::http::error(404));
        EXPECT(!wallet->passed_login);
      }
    }

    SECTION("refresh")
    {
      const auto frame = std::make_shared<response_loop::frame>(lest_env, io);
      wallet->client.init(io, "127.0.0.1", "", acceptor.local_endpoint().port(), no_ssl);
 
      bool done = false;
      std::error_code result{};
      const auto record_response = [&] (auto val) { done = true; result = val; };
      bwallet::refresh(wallet, true, record_response);

      wallet->passed_login = false;
      acceptor.async_accept(frame->server, response_loop{frame});

      SECTION("account is disabled")
      {
        frame->requests = {{"/login", ""}};
        frame->responses = {boost::beast::http::status::forbidden};

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        EXPECT(frame->responses.size() == 0);
        EXPECT(result == lwsf::error::approval);
        EXPECT(!wallet->passed_login);
        EXPECT(wallet->refresh_error == lwsf::error::approval);
      }

      SECTION("get_address_txs unexpectedly fails with queued")
      {
        frame->requests = {
          {"/login", ""},
          {"/upsert_subaddrs", ""},
          {"/feed", ""},
          {"/get_address_txs", ""}
        };
        frame->responses = {
          R"({"new_address": true})",
          "",
          boost::beast::http::status::not_found,
          boost::beast::http::status::forbidden
        };

        bool done2 = false;
        std::error_code result2{};
        bwallet::refresh(wallet, true, [&] (auto val) { done2 = true; result2 = val; });

        while (!done || !done2)
        {
          io.restart();
          io.run_one();
        }

        EXPECT(frame->responses.size() == 0);
        EXPECT(result == lwsf::error::approval);
        EXPECT(result2 == lwsf::error::approval);
        EXPECT(!wallet->passed_login);
        EXPECT(wallet->refresh_error == lwsf::error::approval);
      }

      SECTION("0.3 server")
      {
        frame->requests = {
          {"/login", ""},
          {"/upsert_subaddrs", ""},
          {"/feed", ""},
          {"/get_address_txs", ""},
          {"/get_unspent_outs", ""},
          {"/get_version", ""}
        };
        frame->responses = {
          R"({"new_address": true})",
          "",
          boost::beast::http::status::not_found,
          R"({
            "total_received": "5000",
            "scanned_height": 150,
            "scanned_block_height": 150,
            "start_height": 10,
            "blockchain_height": 200,
            "transactions": [{
              "id": 1,
              "hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "total_received": "5000",
              "total_sent": "10000",
              "unlock_time": 0,
              "spent_outputs": [{
                "amount": "10000",
                "key_image": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee2",
                "tx_pub_key": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee3",
                "out_index": 0,
                "mixin": 15
              }],
              "coinbase": false,
              "mempool": true,
              "mixin": 15
            }]
          })",
          R"({
            "per_byte_fee": 5,
            "fee_mask": 100,
            "amount": "200",
            "outputs": [{ 
              "amount": "5000",
              "index": 5,
              "global_index": "50000",
              "rct": 
                 "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee4",
              "tx_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "tx_prefix_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee5",
              "public_key": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee6",
              "tx_pub_key": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee3",
              "spend_key_images": ["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee2"],
              "timestamp": "2026-01-01T00:00:00Z",
              "height": 0
            }]
          })",
          boost::beast::http::status::not_found
        };

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        const lwsf::internal::rpc::address_meta recipient{0, 0};

        EXPECT(frame->responses.size() == 0);
        EXPECT(result == lwsf::error::subaddr_upgrade);
        EXPECT(wallet->passed_login);
        EXPECT(wallet->refresh_error == lwsf::error::subaddr_upgrade);
        EXPECT(wallet->lookahead_error == lwsf::error::subaddr_upgrade);
        EXPECT(wallet->primary.restore_height == 10);
        EXPECT(wallet->primary.scan_height == 150);
        EXPECT(wallet->primary.requested_start == 10);
        EXPECT(wallet->blockchain_height == 200);
        EXPECT(wallet->fee_mask == 100);
        EXPECT(wallet->per_byte_fee.size() == 1);
        EXPECT(wallet->per_byte_fee.at(0) == 5);
        EXPECT(wallet->primary.txes.size() == 1);
        auto tx = wallet->primary.txes.find(from_hex<crypto::hash>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1"));
        EXPECT(tx != wallet->primary.txes.end());
        EXPECT(tx->second != nullptr);
        EXPECT(tx->second->spends.size() == 0);
        EXPECT(tx->second->receives.size() == 1);
        EXPECT(tx->second->receives.nth(0)->first == from_hex<crypto::public_key>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee6"));
        EXPECT(tx->second->receives.nth(0)->second.tx_pub == from_hex<crypto::public_key>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee3"));
        EXPECT(tx->second->receives.nth(0)->second.amount == 5000);
        EXPECT(tx->second->receives.nth(0)->second.recipient == recipient);
        EXPECT(tx->second->receives.nth(0)->second.index == 5);
        EXPECT(tx->second->receives.nth(0)->second.global_index == 50000);
        EXPECT(bool(tx->second->receives.nth(0)->second.rct_mask));
        EXPECT(wallet->primary.subaccounts.size() == 1);
        EXPECT(wallet->primary.subaccounts.at(0).last == 0);
      }

      SECTION("1.0 server with good lookahead")
      {
        frame->requests = {
          {"/login", ""},
          {"/feed", ""},
          {"/get_address_txs", ""},
          {"/get_unspent_outs", ""},
        };
        frame->responses = {
          R"({"new_address": true, "lookahead": {"maj_i": 50, "min_i": 200}})",
          boost::beast::http::status::not_found,
          R"({
            "total_received": "4000",
            "scanned_height": 175,
            "scanned_block_height": 175,
            "start_height": 10,
            "blockchain_height": 210,
            "lookahead": {"maj_i": 50, "min_i": 200},
            "transactions": [{
              "id": 1,
              "hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "total_received": "4000",
              "total_sent": "10000",
              "unlock_time": 0,
              "spent_outputs": [{
                "amount": "10000",
                "key_image": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee2",
                "tx_pub_key": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee3",
                "out_index": 0,
                "mixin": 15
              }],
              "coinbase": false,
              "mempool": true,
              "mixin": 15
            }]
          })",
          R"({
            "per_byte_fee": 5,
            "fee_mask": 100,
            "fees": [110, 500, 700],
            "amount": "4000",
            "outputs": [{ 
              "amount": "4000",
              "index": 0,
              "global_index": "60000",
              "rct": 
                 "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee4",
              "tx_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "tx_prefix_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee5",
              "public_key": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee6",
              "tx_pub_key": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee3",
              "spend_key_images": ["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee2"],
              "timestamp": "2026-01-01T00:00:00Z",
              "height": 0,
              "recipient": {"maj_i": 1, "min_i": 2}
            }]
          })"
        };

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        const lwsf::internal::rpc::address_meta recipient{1, 2};

        EXPECT(frame->responses.size() == 0);
        EXPECT(result == std::error_code{});
        EXPECT(wallet->passed_login);
        EXPECT(wallet->refresh_error == std::error_code{});
        EXPECT(wallet->lookahead_error == std::error_code{});
        EXPECT(wallet->subaddress_error == std::error_code{});
        EXPECT(wallet->import_error == std::error_code{});
        EXPECT(wallet->primary.restore_height == 10);
        EXPECT(wallet->primary.scan_height == 175);
        EXPECT(wallet->primary.requested_start == 10);
        EXPECT(wallet->blockchain_height == 210);
        EXPECT(wallet->fee_mask == 100);
        EXPECT(wallet->per_byte_fee.size() == 3);
        EXPECT(wallet->per_byte_fee.at(0) == 110);
        EXPECT(wallet->per_byte_fee.at(1) == 500);
        EXPECT(wallet->per_byte_fee.at(2) == 700);
        EXPECT(wallet->primary.txes.size() == 1);
        auto tx = wallet->primary.txes.find(from_hex<crypto::hash>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1"));
        EXPECT(tx != wallet->primary.txes.end());
        EXPECT(tx->second != nullptr);
        EXPECT(tx->second->spends.size() == 0);
        EXPECT(tx->second->receives.size() == 1);
        EXPECT(tx->second->receives.nth(0)->first == from_hex<crypto::public_key>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee6"));
        EXPECT(tx->second->receives.nth(0)->second.tx_pub == from_hex<crypto::public_key>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee3"));
        EXPECT(tx->second->receives.nth(0)->second.amount == 4000);
        EXPECT(tx->second->receives.nth(0)->second.recipient == recipient);
        EXPECT(tx->second->receives.nth(0)->second.index == 0);
        EXPECT(tx->second->receives.nth(0)->second.global_index == 60000);
        EXPECT(bool(tx->second->receives.nth(0)->second.rct_mask));
        EXPECT(wallet->primary.subaccounts.size() == 2);
        EXPECT(wallet->primary.subaccounts.at(0).last == 0);
        EXPECT(wallet->primary.subaccounts.at(1).last == 2);
      }

      SECTION("1.0 server with lookahead fail and limited max subaddresses")
      {
        std::string subs;
        for (unsigned i = 0; i < 50; ++i)
          subs += R"({"key":)" + std::to_string(i) + R"(, "value": [[0, 199]]},)";
        subs.pop_back();

        const std::string upsert_body =
          R"({"address":")" + wallet->get_spend_address({0, 0}) +
          R"(","view_key":")" + to_hex(unwrap(unwrap(wallet->primary.view.sec))) +
          R"(","subaddrs":[{"key":1,"value":[[0,2]]}],"get_all":false})";

        rct::key ringct{};
        crypto::key_image image{};
        lwsf::internal::backend::keypair tx_key{};
        lwsf::internal::backend::keypair output_key{};
        crypto::generate_keys(tx_key.pub, tx_key.sec);
        {
          crypto::secret_key scalar{};
          crypto::key_derivation derived{};
          EXPECT(crypto::generate_key_derivation(tx_key.pub, wallet->primary.view.sec, derived));
          EXPECT(crypto::derive_public_key(derived, 3, wallet->primary.spend.pub, output_key.pub));
          crypto::derive_secret_key(derived, 3, wallet->primary.spend.sec, output_key.sec);
          crypto::generate_key_image(output_key.pub, output_key.sec, image);

          crypto::derivation_to_scalar(derived, 3, scalar);

          rct::ecdhTuple commitment{};
          rct::ecdhDecode(commitment, rct::sk2rct(scalar), true);
          ringct = commitment.mask;
        }

        EXPECT(wallet->primary.subaccounts.size() == 2); // from last section
        frame->requests = {
          {"/login", ""},
          {"/upsert_subaddrs", upsert_body},
          {"/feed", ""},
          {"/get_address_txs", ""},
          {"/get_unspent_outs", ""},
          {"/get_version", ""},
          {"/get_subaddrs", ""}
        };
        frame->responses = {
          R"({"new_address": true, "lookahead": {"maj_i": 50, "min_i": 200}})",
          "",
          boost::beast::http::status::not_found,
          R"({
            "total_received": "4000",
            "scanned_height": 175,
            "scanned_block_height": 175,
            "start_height": 5,
            "blockchain_height": 210,
            "lookahead": {"maj_i": 50, "min_i": 200},
            "lookahead_fail": 150,
            "transactions": [{
              "id": 1,
              "hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "total_received": "4000",
              "total_sent": "10000",
              "unlock_time": 0,
              "spent_outputs": [{
                "amount": "10000",
                "key_image": ")" + to_hex(image) + R"(",
                "tx_pub_key": ")" + to_hex(tx_key.pub) + R"(",
                "out_index": 3,
                "mixin": 15
              }],
              "coinbase": false,
              "mempool": true,
              "mixin": 15
            }]
          })",
          R"({
            "per_byte_fee": 5,
            "fee_mask": 100,
            "fees": [110, 500, 700],
            "amount": "4000",
            "lookahead_fail": 150,
            "outputs": [{ 
              "amount": "4000",
              "index": 3,
              "global_index": "60000",
              "rct": "recomputed",
              "tx_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "tx_prefix_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee5",
              "public_key": ")" + to_hex(output_key.pub) + R"(",
              "tx_pub_key": ")" + to_hex(tx_key.pub) + R"(",
              "spend_key_images": [")" + to_hex(image) + R"("],
              "timestamp": "2026-01-01T00:00:00Z",
              "height": 150,
              "recipient": {"maj_i": 1, "min_i": 2}
            }]
          })",
          R"({"max_subaddresses": 10000})",
          R"({"all_subaddrs": [)" + subs + "]}"
        };

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        const lwsf::internal::rpc::address_meta sender{0, 0};
        const lwsf::internal::rpc::address_meta recipient{1, 2};

        EXPECT(frame->responses.size() == 0);
        EXPECT(result == lwsf::error::subaddr_ahead);
        EXPECT(wallet->passed_login);
        EXPECT(wallet->refresh_error == lwsf::error::subaddr_ahead);
        EXPECT(wallet->lookahead_error == lwsf::error::subaddr_ahead);
        EXPECT(wallet->subaddress_error == std::error_code{});
        EXPECT(wallet->import_error == std::error_code{});
        EXPECT(wallet->primary.restore_height == 5);
        EXPECT(wallet->primary.scan_height == 175);
        EXPECT(wallet->primary.requested_start == 5);
        EXPECT(wallet->blockchain_height == 210);
        EXPECT(wallet->fee_mask == 100);
        EXPECT(wallet->per_byte_fee.size() == 3);
        EXPECT(wallet->per_byte_fee.at(0) == 110);
        EXPECT(wallet->per_byte_fee.at(1) == 500);
        EXPECT(wallet->per_byte_fee.at(2) == 700);
        EXPECT(wallet->primary.txes.size() == 1);
        auto tx = wallet->primary.txes.find(from_hex<crypto::hash>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1"));
        EXPECT(tx != wallet->primary.txes.end());
        EXPECT(tx->second != nullptr);
        EXPECT(tx->second->spends.size() == 1);
        EXPECT(tx->second->spends.nth(0)->first == image);
        EXPECT(tx->second->spends.nth(0)->second.amount == 10000);
        EXPECT(tx->second->spends.nth(0)->second.sender == sender);
        EXPECT(tx->second->spends.nth(0)->second.tx_pub == tx_key.pub);
        EXPECT(tx->second->spends.nth(0)->second.output_pub == output_key.pub);
        EXPECT(tx->second->receives.size() == 1);
        EXPECT(tx->second->receives.nth(0)->first == output_key.pub);
        EXPECT(tx->second->receives.nth(0)->second.tx_pub == tx_key.pub); 
        EXPECT(tx->second->receives.nth(0)->second.amount == 4000);
        EXPECT(tx->second->receives.nth(0)->second.recipient == recipient);
        EXPECT(tx->second->receives.nth(0)->second.index == 3);
        EXPECT(tx->second->receives.nth(0)->second.global_index == 60000);
        EXPECT(bool(tx->second->receives.nth(0)->second.rct_mask));
        EXPECT(*tx->second->receives.nth(0)->second.rct_mask == ringct);
        EXPECT(wallet->primary.subaccounts.size() == 2);
        EXPECT(wallet->primary.subaccounts.at(0).last == 0);
        EXPECT(wallet->primary.subaccounts.at(1).last == 2);
      }

      SECTION("1.0 server with lookahead fail and max subaddress availability")
      {
        std::string subs;
        for (unsigned i = 0; i < 50; ++i)
          subs += R"({"key":)" + std::to_string(i) + R"(, "value": [[0, 199]]},)";
        subs.pop_back();

        const std::string upsert_body =
          R"({"address":")" + wallet->get_spend_address({0, 0}) +
          R"(","view_key":")" + to_hex(unwrap(unwrap(wallet->primary.view.sec))) +
          R"(","subaddrs":[{"key":1,"value":[[0,2]]}],"get_all":false})";

        const std::string import_body =
          R"({"address":")" + wallet->get_spend_address({0, 0}) +
          R"(","view_key":")" + to_hex(unwrap(unwrap(wallet->primary.view.sec))) +
          R"(","from_height":150,"lookahead":{"maj_i":50,"min_i":200}})";

        rct::key ringct{};
        crypto::key_image image{};
        lwsf::internal::backend::keypair tx_key{};
        lwsf::internal::backend::keypair output_key{};
        crypto::generate_keys(tx_key.pub, tx_key.sec);
        {
          crypto::secret_key scalar{};
          crypto::key_derivation derived{};
          EXPECT(crypto::generate_key_derivation(tx_key.pub, wallet->primary.view.sec, derived));
          EXPECT(crypto::derive_public_key(derived, 3, wallet->primary.spend.pub, output_key.pub));
          crypto::derive_secret_key(derived, 3, wallet->primary.spend.sec, output_key.sec);
          crypto::generate_key_image(output_key.pub, output_key.sec, image);

          crypto::derivation_to_scalar(derived, 3, scalar);

          rct::ecdhTuple commitment{};
          rct::ecdhDecode(commitment, rct::sk2rct(scalar), true);
          ringct = commitment.mask;
        }

        EXPECT(wallet->primary.subaccounts.size() == 2); // from last section
        frame->requests = {
          {"/login", ""},
          {"/upsert_subaddrs", upsert_body},
          {"/feed", ""},
          {"/get_address_txs", ""},
          {"/get_unspent_outs", ""},
          {"/get_version", ""},
          {"/get_subaddrs", ""},
          {"/import_wallet_request", import_body}
        };
        frame->responses = {
          R"({"new_address": true, "lookahead": {"maj_i": 50, "min_i": 200}})",
          "",
          boost::beast::http::status::not_found,
          R"({
            "total_received": "4000",
            "scanned_height": 175,
            "scanned_block_height": 175,
            "start_height": 5,
            "blockchain_height": 210,
            "lookahead": {"maj_i": 50, "min_i": 200},
            "lookahead_fail": 150,
            "transactions": [{
              "id": 1,
              "hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "total_received": "4000",
              "total_sent": "10000",
              "unlock_time": 0,
              "spent_outputs": [{
                "amount": "10000",
                "key_image": ")" + to_hex(image) + R"(",
                "tx_pub_key": ")" + to_hex(tx_key.pub) + R"(",
                "out_index": 3,
                "mixin": 15
              }],
              "coinbase": false,
              "mempool": true,
              "mixin": 15
            }]
          })",
          R"({
            "per_byte_fee": 5,
            "fee_mask": 100,
            "fees": [110, 500, 700],
            "amount": "4000",
            "lookahead_fail": 150,
            "outputs": [{ 
              "amount": "4000",
              "index": 3,
              "global_index": "60000",
              "rct": "recomputed",
              "tx_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "tx_prefix_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee5",
              "public_key": ")" + to_hex(output_key.pub) + R"(",
              "tx_pub_key": ")" + to_hex(tx_key.pub) + R"(",
              "spend_key_images": [")" + to_hex(image) + R"("],
              "timestamp": "2026-01-01T00:00:00Z",
              "height": 150,
              "recipient": {"maj_i": 1, "min_i": 2}
            }]
          })",
          R"({"max_subaddresses": 30000})",
          R"({"all_subaddrs": [)" + subs + "]}",
          R"({"lookahead": {"maj_i": 50, "min_i": 200}, "status": "OK", "new_request": true, "request_fulfilled": true})"
        };

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        const lwsf::internal::rpc::address_meta sender{0, 0};
        const lwsf::internal::rpc::address_meta recipient{1, 2};

        EXPECT(frame->responses.size() == 0);
        EXPECT(result == std::error_code{});
        EXPECT(wallet->passed_login);
        EXPECT(wallet->refresh_error == std::error_code{});
        EXPECT(wallet->lookahead_error == std::error_code{});
        EXPECT(wallet->subaddress_error == std::error_code{});
        EXPECT(wallet->import_error == std::error_code{});
        EXPECT(wallet->primary.restore_height == 5);
        EXPECT(wallet->primary.scan_height == 175);
        EXPECT(wallet->primary.requested_start == 5);
        EXPECT(wallet->blockchain_height == 210);
        EXPECT(wallet->fee_mask == 100);
        EXPECT(wallet->per_byte_fee.size() == 3);
        EXPECT(wallet->per_byte_fee.at(0) == 110);
        EXPECT(wallet->per_byte_fee.at(1) == 500);
        EXPECT(wallet->per_byte_fee.at(2) == 700);
        EXPECT(wallet->primary.txes.size() == 1);
        auto tx = wallet->primary.txes.find(from_hex<crypto::hash>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1"));
        EXPECT(tx != wallet->primary.txes.end());
        EXPECT(tx->second != nullptr);
        EXPECT(tx->second->spends.size() == 1);
        EXPECT(tx->second->spends.nth(0)->first == image);
        EXPECT(tx->second->spends.nth(0)->second.amount == 10000);
        EXPECT(tx->second->spends.nth(0)->second.sender == sender);
        EXPECT(tx->second->spends.nth(0)->second.tx_pub == tx_key.pub);
        EXPECT(tx->second->spends.nth(0)->second.output_pub == output_key.pub);
        EXPECT(tx->second->receives.size() == 1);
        EXPECT(tx->second->receives.nth(0)->first == output_key.pub);
        EXPECT(tx->second->receives.nth(0)->second.tx_pub == tx_key.pub); 
        EXPECT(tx->second->receives.nth(0)->second.amount == 4000);
        EXPECT(tx->second->receives.nth(0)->second.recipient == recipient);
        EXPECT(tx->second->receives.nth(0)->second.index == 3);
        EXPECT(tx->second->receives.nth(0)->second.global_index == 60000);
        EXPECT(bool(tx->second->receives.nth(0)->second.rct_mask));
        EXPECT(*tx->second->receives.nth(0)->second.rct_mask == ringct);
        EXPECT(wallet->primary.subaccounts.size() == 2);
        EXPECT(wallet->primary.subaccounts.at(0).last == 0);
        EXPECT(wallet->primary.subaccounts.at(1).last == 2);
      }

      SECTION("1.0 server with lookahead fail and new start")
      {
        wallet->primary.requested_start = 1;

        std::string subs;
        for (unsigned i = 0; i < 50; ++i)
          subs += R"({"key":)" + std::to_string(i) + R"(, "value": [[0, 199]]},)";
        subs.pop_back();

        const std::string upsert_body =
          R"({"address":")" + wallet->get_spend_address({0, 0}) +
          R"(","view_key":")" + to_hex(unwrap(unwrap(wallet->primary.view.sec))) +
          R"(","subaddrs":[{"key":1,"value":[[0,2]]}],"get_all":false})";

        const std::string import_body =
          R"({"address":")" + wallet->get_spend_address({0, 0}) +
          R"(","view_key":")" + to_hex(unwrap(unwrap(wallet->primary.view.sec))) +
          R"(","from_height":1,"lookahead":{"maj_i":50,"min_i":200}})";

        rct::key ringct{};
        crypto::key_image image{};
        lwsf::internal::backend::keypair tx_key{};
        lwsf::internal::backend::keypair output_key{};
        crypto::generate_keys(tx_key.pub, tx_key.sec);
        {
          crypto::secret_key scalar{};
          crypto::key_derivation derived{};
          EXPECT(crypto::generate_key_derivation(tx_key.pub, wallet->primary.view.sec, derived));
          EXPECT(crypto::derive_public_key(derived, 3, wallet->primary.spend.pub, output_key.pub));
          crypto::derive_secret_key(derived, 3, wallet->primary.spend.sec, output_key.sec);
          crypto::generate_key_image(output_key.pub, output_key.sec, image);

          crypto::derivation_to_scalar(derived, 3, scalar);

          rct::ecdhTuple commitment{};
          rct::ecdhDecode(commitment, rct::sk2rct(scalar), true);
          ringct = commitment.mask;
        }

        EXPECT(wallet->primary.subaccounts.size() == 2); // from last section
        frame->requests = {
          {"/login", ""},
          {"/upsert_subaddrs", upsert_body},
          {"/feed", ""},
          {"/get_address_txs", ""},
          {"/get_unspent_outs", ""},
          {"/import_wallet_request", import_body}
        };
        frame->responses = {
          R"({"new_address": true, "lookahead": {"maj_i": 50, "min_i": 200}})",
          "",
          boost::beast::http::status::not_found,
          R"({
            "total_received": "4000",
            "scanned_height": 175,
            "scanned_block_height": 175,
            "start_height": 5,
            "blockchain_height": 210,
            "lookahead": {"maj_i": 50, "min_i": 200},
            "lookahead_fail": 150,
            "transactions": [{
              "id": 1,
              "hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "total_received": "4000",
              "total_sent": "10000",
              "unlock_time": 0,
              "spent_outputs": [{
                "amount": "10000",
                "key_image": ")" + to_hex(image) + R"(",
                "tx_pub_key": ")" + to_hex(tx_key.pub) + R"(",
                "out_index": 3,
                "mixin": 15
              }],
              "coinbase": false,
              "mempool": true,
              "mixin": 15
            }]
          })",
          R"({
            "per_byte_fee": 5,
            "fee_mask": 100,
            "fees": [110, 500, 700],
            "amount": "4000",
            "lookahead_fail": 150,
            "outputs": [{ 
              "amount": "4000",
              "index": 3,
              "global_index": "60000",
              "rct": "recomputed",
              "tx_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1",
              "tx_prefix_hash": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee5",
              "public_key": ")" + to_hex(output_key.pub) + R"(",
              "tx_pub_key": ")" + to_hex(tx_key.pub) + R"(",
              "spend_key_images": [")" + to_hex(image) + R"("],
              "timestamp": "2026-01-01T00:00:00Z",
              "height": 150,
              "recipient": {"maj_i": 1, "min_i": 2}
            }]
          })",
          R"({"lookahead": {"maj_i": 50, "min_i": 200}, "status": "OK", "new_request": true, "request_fulfilled": true})"
        };

        while (!done)
        {
          io.restart();
          io.run_one();
        }

        const lwsf::internal::rpc::address_meta sender{0, 0};
        const lwsf::internal::rpc::address_meta recipient{1, 2};

        EXPECT(frame->responses.size() == 0);
        EXPECT(result == std::error_code{});
        EXPECT(wallet->passed_login);
        EXPECT(wallet->refresh_error == std::error_code{});
        EXPECT(wallet->lookahead_error == std::error_code{});
        EXPECT(wallet->subaddress_error == std::error_code{});
        EXPECT(wallet->import_error == std::error_code{});
        EXPECT(wallet->primary.restore_height == 1);
        EXPECT(wallet->primary.scan_height == 175);
        EXPECT(wallet->primary.requested_start == 1);
        EXPECT(wallet->blockchain_height == 210);
        EXPECT(wallet->fee_mask == 100);
        EXPECT(wallet->per_byte_fee.size() == 3);
        EXPECT(wallet->per_byte_fee.at(0) == 110);
        EXPECT(wallet->per_byte_fee.at(1) == 500);
        EXPECT(wallet->per_byte_fee.at(2) == 700);
        EXPECT(wallet->primary.txes.size() == 1);
        auto tx = wallet->primary.txes.find(from_hex<crypto::hash>("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee1"));
        EXPECT(tx != wallet->primary.txes.end());
        EXPECT(tx->second != nullptr);
        EXPECT(tx->second->spends.size() == 1);
        EXPECT(tx->second->spends.nth(0)->first == image);
        EXPECT(tx->second->spends.nth(0)->second.amount == 10000);
        EXPECT(tx->second->spends.nth(0)->second.sender == sender);
        EXPECT(tx->second->spends.nth(0)->second.tx_pub == tx_key.pub);
        EXPECT(tx->second->spends.nth(0)->second.output_pub == output_key.pub);
        EXPECT(tx->second->receives.size() == 1);
        EXPECT(tx->second->receives.nth(0)->first == output_key.pub);
        EXPECT(tx->second->receives.nth(0)->second.tx_pub == tx_key.pub); 
        EXPECT(tx->second->receives.nth(0)->second.amount == 4000);
        EXPECT(tx->second->receives.nth(0)->second.recipient == recipient);
        EXPECT(tx->second->receives.nth(0)->second.index == 3);
        EXPECT(tx->second->receives.nth(0)->second.global_index == 60000);
        EXPECT(bool(tx->second->receives.nth(0)->second.rct_mask));
        EXPECT(*tx->second->receives.nth(0)->second.rct_mask == ringct);
        EXPECT(wallet->primary.subaccounts.size() == 2);
        EXPECT(wallet->primary.subaccounts.at(0).last == 0);
        EXPECT(wallet->primary.subaccounts.at(1).last == 2);
      }
    }

    SECTION("call rpcs in randomized order with threads")
    {
      static constexpr const unsigned high_level_calls = 1000;

      const auto frame = std::make_shared<dummy_server::frame>(io);
      wallet->client.init(io, "127.0.0.1", "", acceptor.local_endpoint().port(), no_ssl);
      wallet->primary.subaccounts.emplace_back().last = 1;
      acceptor.async_accept(frame->server, dummy_server{frame});

      std::atomic<unsigned> count{0};
      const auto completed = [&] (auto) { ++count; };

      const std::array<std::function<void()>, 9> rpcs
      {{
        std::bind(bwallet::login_is_new, wallet, completed),
        std::bind(bwallet::refresh, wallet, true, completed),
        std::bind(bwallet::get_fees, wallet, completed),
        std::bind(bwallet::register_subaccount, wallet, 1, completed),
        std::bind(bwallet::register_subaddress, wallet, 1, 0, completed),
        std::bind(bwallet::set_lookahead, wallet, 1, 1, completed),
        std::bind(bwallet::restore_height_raw, wallet, 0, completed),
        std::bind(bwallet::get_decoys, wallet, empty_decoys{}, completed),
        std::bind(bwallet::send_tx, wallet, empty_slice{}, completed)
      }};

      struct joiner
      {
        boost::thread thread;

        joiner(const joiner&) = delete;
        joiner(joiner&&) = default;
        ~joiner() noexcept { if (thread.joinable()) thread.join(); }
      };
      std::vector<joiner> threads;

      struct on_exit_
      {
        boost::asio::io_context& io;
        ~on_exit_() noexcept { io.stop(); }
      } on_exit{io};

      std::string asio_fail;
      boost::mutex sync_asio;
      const auto run_asio = [&]
      {
        try { (io.run()); }
        catch (const std::exception& e)
        {
          io.stop();
          const boost::lock_guard<boost::mutex> lock{sync_asio};
          asio_fail = e.what();
        }
      };
      const auto run_client = [&] 
      {
        static_assert(high_level_calls % 2 == 0);
        static_assert(0 < rpcs.size());
        static_assert(rpcs.size() <= std::numeric_limits<unsigned>::max());

        std::mt19937 eng(crypto::rand<std::uint32_t>());
        std::uniform_int_distribution<unsigned> dist(0, rpcs.size() - 1);

        unsigned i = high_level_calls / 2;
        while (i--)
        {
          rpcs.at(dist(eng))();
          // the above call is much quicker than the response threads
          boost::this_thread::sleep_for(boost::chrono::milliseconds{1});
        }
      };

      threads.push_back(joiner{boost::thread{run_asio}});
      threads.push_back(joiner{boost::thread{run_asio}});
      threads.push_back(joiner{boost::thread{run_client}});
      run_client();

      while (count < high_level_calls && !io.stopped())
        boost::this_thread::sleep_for(boost::chrono::milliseconds{50});

      const boost::lock_guard<boost::mutex> lock{sync_asio};
      EXPECT(asio_fail == "");
      EXPECT(count == high_level_calls);
      EXPECT(!io.stopped());
    }
  }
}

LWS_CASE("backend::wallet /feed (websocket)")
{
  using bwallet = lwsf::internal::backend::wallet;
  using tcp = boost::asio::ip::tcp;
  const auto no_ssl = epee::net_utils::ssl_support_t::e_ssl_support_disabled;

  SETUP("base empty wallet and basic server")
  {
    boost::asio::io_context io;
    const auto wallet = std::make_shared<lwsf::internal::backend::wallet>(io);
    crypto::generate_keys(wallet->primary.view.pub, wallet->primary.view.sec);
    crypto::generate_keys(wallet->primary.spend.pub, wallet->primary.spend.sec);
    wallet->primary.address = wallet->get_spend_address({0, 0});

    tcp::acceptor acceptor{io, tcp::endpoint(tcp::v4(), 0)};
    acceptor.listen();

    const auto login_verify = [&] (std::string sub)
    {
      EXPECT(boost::string_view{sub}.starts_with("login:"));
      sub.erase(0, std::strlen("login:"));

      login user{};
      EXPECT(lwsf::wire::msgpack::from_bytes(epee::byte_slice{std::move(sub)}, user) == std::error_code{});
      EXPECT(user.account.address == wallet->get_spend_address({0, 0}));
      EXPECT(user.account.view_key == wallet->primary.view.sec);
    };

    const std::string upsert_body =
      R"({"address":")" + wallet->get_spend_address({0, 0}) +
      R"(","view_key":")" + to_hex(unwrap(unwrap(wallet->primary.view.sec))) +
      R"(","subaddrs":[{"key":1,"value":[[0,2]]}],"get_all":false})";

    const auto frame = std::make_shared<response_loop::frame>(lest_env, io);
    const auto frame2 = std::make_shared<response_loop::frame>(lest_env, io);
    wallet->client.init(io, "127.0.0.1", "", acceptor.local_endpoint().port(), no_ssl);

    bool done = false;
    std::size_t refreshed = 0;
    std::error_code result{};
    std::error_code ws_result{};
    const auto record_response = [&] (auto val) { done = true; result = val; };
    bwallet::refresh(wallet, true, record_response);

    wallet->passed_login = false;
    wallet->feed_disabled = false;
    wallet->on_feed_fail = [&] (auto val) { ws_result = val; };
    wallet->on_feed_refresh = [&] (auto err) { EXPECT(!err); ++refreshed; };
    acceptor.async_accept(frame->server, response_loop{frame});

    SECTION("feed is aborted during upgrade")
    {
      wallet->on_feed_fail = [&] (auto err) {
        EXPECT(err == boost::system::error_code{boost::beast::websocket::error::upgrade_declined});
        acceptor.async_accept(frame2->server, response_loop{frame2});
      };

      frame->requests = {
        {"/login", ""},
        {"/feed", ""},
        {"/feed", ""}
      };
      frame->responses = {
        R"({"new_address": true, "lookahead": {"maj_i": 50, "min_i": 200}})",
        boost::beast::http::status::not_implemented,
        boost::beast::http::status::not_found
      };

      frame2->requests = {{"/get_address_txs", ""}};
      frame2->responses = {boost::beast::http::status::forbidden};

      while (!done)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(refreshed == 0);
      EXPECT(!wallet->on_feed_fail);
      EXPECT(!wallet->on_feed_refresh);
      EXPECT(frame->responses.size() == 0);
      EXPECT(frame2->responses.size() == 0);
      EXPECT(result == lwsf::error::approval);
      EXPECT(!wallet->passed_login);
      EXPECT(wallet->feed_disabled);
      EXPECT(wallet->refresh_error == lwsf::error::approval);
    }

    SECTION("feed is aborted after upgrade")
    {
      wallet->on_feed_fail = [&] (auto err) {
        EXPECT(err == lwsf::error::bad_feed_prefix);
        acceptor.async_accept(frame2->server, response_loop{frame2});
      };

      const std::string error =R"({"msg": "account not found", "code": 1})";

      frame->requests = {
        {"/login", ""},
        {"/feed", ""},
        {"/feed", ""}
      };
      frame->responses = {
        R"({"new_address": true, "lookahead": {"maj_i": 50, "min_i": 200}})",
        boost::beast::http::status::not_implemented,
        boost::beast::http::status::switching_protocols
      };

      while (!frame->ws)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(refreshed == 0);
      EXPECT(wallet->on_feed_fail);
      EXPECT(wallet->on_feed_refresh);
      EXPECT(frame->responses.size() == 0);
      EXPECT(frame2->responses.size() == 0);
      EXPECT(result == std::error_code{});
      EXPECT(wallet->passed_login);
      EXPECT(!wallet->feed_disabled);
      EXPECT(wallet->refresh_error == std::error_code{});
      EXPECT(wallet->lookahead_error == std::error_code{});
      EXPECT(wallet->subaddress_error == std::error_code{});
      EXPECT(wallet->import_error == std::error_code{});

      wallet->on_feed_refresh =
        [&] (auto err) { EXPECT(err == lwsf::error::bad_feed_prefix); ++refreshed; };

      lwsf_test::net::push::async_read(frame->ws, [&] (auto user) {
        login_verify(user.value());
        lwsf_test::net::push::async_pub(
          frame->ws, "error:" + to_msgpack(error), [&] (auto err) { EXPECT(!err); }
        );
      });

      frame2->requests = {{"/get_address_txs", ""}};
      frame2->responses = {boost::beast::http::status::forbidden};

      while (!done)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(refreshed == 1);
      EXPECT(!wallet->on_feed_fail);
      EXPECT(!wallet->on_feed_refresh);
      EXPECT(frame->responses.size() == 0);
      EXPECT(frame2->responses.size() == 0);
      EXPECT(result == lwsf::error::approval);
      EXPECT(!wallet->passed_login);
      EXPECT(wallet->feed_disabled);
      EXPECT(wallet->refresh_error == lwsf::error::approval);
    }

    SECTION("feed sync (no initial txes)")
    {
      rct::key ringct{};
      lwsf::internal::backend::keypair tx_key{};
      lwsf::internal::backend::keypair output_key{};
      crypto::generate_keys(tx_key.pub, tx_key.sec);
      const crypto::hash tx_hash = crypto::rand<crypto::hash>();
      const crypto::hash prefix_hash = crypto::rand<crypto::hash>();
      {
        crypto::secret_key scalar{};
        crypto::key_derivation derived{};
        EXPECT(crypto::generate_key_derivation(tx_key.pub, wallet->primary.view.sec, derived));
        EXPECT(crypto::derive_public_key(derived, 3, wallet->primary.spend.pub, output_key.pub));
        crypto::derive_secret_key(derived, 3, wallet->primary.spend.sec, output_key.sec);

        crypto::derivation_to_scalar(derived, 3, scalar);

        rct::ecdhTuple commitment{};
        rct::ecdhDecode(commitment, rct::sk2rct(scalar), true);
        ringct = commitment.mask;
      }

      const std::string tx_sync =
        R"({
          "scanned_block_height": 950,
          "start_height": 900,
          "blockchain_height": 1000,
          "lookahead": {"maj_i": 50, "min_i": 200}
        })";

      const std::string blocks =
        R"({
          "scan_start": 950,
          "scan_end": 975,
          "blockchain_height": 1001,
          "transactions": [{
            "hash": ")" + to_hex(tx_hash) + R"(",
            "prefix_hash": ")" + to_hex(prefix_hash) + R"(",
            "timestamp": 9000,
            "fee": 105,
            "unlock_time": 5000,
            "height": 961,
            "mixin": 16,
            "receives": [{
              "amount": 2566,
              "public_key": ")" + to_hex(output_key.pub) + R"(",
              "index": 3,
              "id": {"legacy": {"amount": 0, "index": 1000}},
              "tx_pub_key": ")" + to_hex(tx_key.pub) + R"(",
              "rct": ")" + to_hex(ringct) + R"("
            }]
          }]
        })";

      const std::string warning = R"({"msg": "e", "height": 960, "code": 4})";

      frame->requests = {
        {"/login", ""},
        {"/feed", ""},
        {"/feed", ""}
      };
      frame->responses = {
        R"({"new_address": true, "lookahead": {"maj_i": 50, "min_i": 200}})",
        boost::beast::http::status::not_implemented,
        boost::beast::http::status::switching_protocols
      };

      while (!frame->ws)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(!done);
      EXPECT(refreshed == 0);
      EXPECT(!wallet->feed_disabled);
      EXPECT(wallet->on_feed_fail);
      EXPECT(wallet->on_feed_refresh);
      EXPECT(frame->responses.size() == 0);
      EXPECT(result == std::error_code{});
      EXPECT(wallet->refresh_error == std::error_code{});
      EXPECT(wallet->lookahead_error == std::error_code{});
      EXPECT(wallet->subaddress_error == std::error_code{});
      EXPECT(wallet->import_error == std::error_code{});
      EXPECT(wallet->passed_login);

      lwsf_test::net::push::async_read(frame->ws, [&] (auto user) {
        login_verify(user.value());
        lwsf_test::net::push::async_pub(
          frame->ws, "tx_sync:" + to_msgpack(tx_sync), [&] (auto err) { EXPECT(!err); }
        );
      });

      while (!done)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(refreshed == 1);
      EXPECT(result == std::error_code{});
      EXPECT(ws_result == std::error_code{});
      EXPECT(wallet->on_feed_fail);
      EXPECT(wallet->on_feed_refresh);
      EXPECT(wallet->refresh_error == std::error_code{});
      EXPECT(wallet->lookahead_error == std::error_code{});
      EXPECT(wallet->subaddress_error == std::error_code{});
      EXPECT(wallet->import_error == std::error_code{});
      EXPECT(wallet->primary.restore_height == 900);
      EXPECT(wallet->primary.scan_height == 950);
      EXPECT(wallet->primary.requested_start == 900);
      EXPECT(wallet->blockchain_height == 1000);
      EXPECT(wallet->primary.txes.empty());

      lwsf_test::net::push::async_pub(
        frame->ws, "blocks:" + to_msgpack(blocks), [&] (auto err) { EXPECT(!err); }
      );

      while (refreshed <= 1)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(refreshed == 2);
      EXPECT(result == std::error_code{});
      EXPECT(ws_result == std::error_code{});
      EXPECT(!wallet->feed_disabled);
      EXPECT(wallet->on_feed_fail);
      EXPECT(wallet->on_feed_refresh);
      EXPECT(wallet->refresh_error == std::error_code{});
      EXPECT(wallet->lookahead_error == std::error_code{});
      EXPECT(wallet->subaddress_error == std::error_code{});
      EXPECT(wallet->import_error == std::error_code{});
      EXPECT(wallet->primary.restore_height == 900);
      EXPECT(wallet->primary.scan_height == 975);
      EXPECT(wallet->primary.requested_start == 900);
      EXPECT(wallet->blockchain_height == 1001);
      EXPECT(wallet->primary.txes.size() == 1);
      EXPECT(wallet->primary.txes.count(tx_hash) == 1);
      const auto tx = wallet->primary.txes.at(tx_hash);
      EXPECT(tx != nullptr);
      EXPECT(tx->spends.empty());
      EXPECT(tx->receives.size() == 1);
      EXPECT(tx->receives.count(output_key.pub) == 1);
      const auto& in = tx->receives.at(output_key.pub);
      EXPECT(in.global_index == 1000);
      EXPECT(in.amount == 2566);
      EXPECT(in.recipient == lwsf::internal::rpc::address_meta{});
      EXPECT(in.index == 3);
      EXPECT(bool(in.rct_mask));
      EXPECT(in.rct_mask.value_or(rct::key{}) == ringct);
      EXPECT(in.tx_pub == tx_key.pub);
      EXPECT(tx->transfers.empty());
      EXPECT(tx->description.empty());
      EXPECT(bool(tx->timestamp));
      EXPECT(tx->timestamp.value_or(std::chrono::system_clock::time_point{}) == std::chrono::system_clock::time_point{std::chrono::seconds{9000}});
      EXPECT(bool(tx->height));
      EXPECT(tx->height.value_or(0) == 961);
      EXPECT(tx->amount == 2566);
      EXPECT(tx->fee == 105);
      EXPECT(tx->unlock_time == 5000);
      EXPECT(tx->direction == Monero::TransactionInfo::Direction_In);
      EXPECT(std::get_if<lwsf::internal::rpc::empty>(std::addressof(tx->payment_id)));
      EXPECT(tx->id == tx_hash);
      EXPECT(tx->prefix == prefix_hash);
      EXPECT(tx->coinbase == false);
      EXPECT(tx->failed == false);

      lwsf_test::net::push::async_pub(
        frame->ws, "warning:" + to_msgpack(warning), [&] (auto err) { EXPECT(!err); }
      );

      while (refreshed <= 2)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(refreshed == 3);
      EXPECT(result == std::error_code{});
      EXPECT(ws_result == std::error_code{});
      EXPECT(!wallet->feed_disabled);
      EXPECT(wallet->on_feed_fail);
      EXPECT(wallet->on_feed_refresh);
      EXPECT(wallet->refresh_error == std::error_code{});
      EXPECT(wallet->lookahead_error == std::error_code{});
      EXPECT(wallet->subaddress_error == std::error_code{});
      EXPECT(wallet->import_error == std::error_code{});
      EXPECT(wallet->primary.restore_height == 900);
      EXPECT(wallet->primary.scan_height == 960);
      EXPECT(wallet->primary.requested_start == 900);
      EXPECT(wallet->blockchain_height == 960);
      EXPECT(wallet->primary.txes.empty());
    }

    SECTION("feed sync (initial txes)")
    {
      rct::key ringct{};
      rct::key ringct2{};
      crypto::key_image image{};
      lwsf::internal::backend::keypair tx_key{};
      lwsf::internal::backend::keypair tx_key2{};
      lwsf::internal::backend::keypair output_key{};
      lwsf::internal::backend::keypair output_key2{};
      crypto::generate_keys(tx_key.pub, tx_key.sec);
      crypto::generate_keys(tx_key2.pub, tx_key2.sec);
      const crypto::hash8 pid = crypto::rand<crypto::hash8>();
      const crypto::hash tx_hash = crypto::rand<crypto::hash>();
      const crypto::hash tx_hash2 = crypto::rand<crypto::hash>();
      const crypto::hash prefix_hash = crypto::rand<crypto::hash>();
      const crypto::hash prefix_hash2 = crypto::rand<crypto::hash>();
      {
        crypto::secret_key scalar{};
        crypto::key_derivation derived{};
        EXPECT(crypto::generate_key_derivation(tx_key.pub, wallet->primary.view.sec, derived));
        EXPECT(crypto::derive_public_key(derived, 0, wallet->primary.spend.pub, output_key.pub));
        crypto::derive_secret_key(derived, 0, wallet->primary.spend.sec, output_key.sec);
        crypto::generate_key_image(output_key.pub, output_key.sec, image);

        crypto::derivation_to_scalar(derived, 0, scalar);

        rct::ecdhTuple commitment{};
        rct::ecdhDecode(commitment, rct::sk2rct(scalar), true);
        ringct = commitment.mask;
      }
      {
        crypto::secret_key scalar{};
        crypto::key_derivation derived{};
        EXPECT(crypto::generate_key_derivation(tx_key2.pub, wallet->primary.view.sec, derived));
        EXPECT(crypto::derive_public_key(derived, 3, wallet->primary.spend.pub, output_key2.pub));
        crypto::derive_secret_key(derived, 3, wallet->primary.spend.sec, output_key2.sec);

        crypto::derivation_to_scalar(derived, 3, scalar);

        rct::ecdhTuple commitment{};
        rct::ecdhDecode(commitment, rct::sk2rct(scalar), true);
        ringct2 = commitment.mask;
      }

      const std::string tx_sync =
        R"({
          "scanned_block_height": 1950,
          "start_height": 900,
          "blockchain_height": 11000,
          "lookahead": {"maj_i": 50, "min_i": 200},
          "transactions": [
            {
              "hash": ")" + to_hex(tx_hash) + R"(",
              "prefix_hash": ")" + to_hex(prefix_hash) + R"(",
              "timestamp": 7000,
              "fee": 103,
              "unlock_time": 4000,
              "height": 1955,
              "mixin": 16,
              "receives": [{
                "amount": 1366,
                "public_key": ")" + to_hex(output_key.pub) + R"(",
                "index": 0,
                "id": {"legacy": {"amount": 0, "index": 1000}},
                "tx_pub_key": ")" + to_hex(tx_key.pub) + R"(",
                "rct": ")" + to_hex(ringct) + R"("
              }]
            },{
              "hash": ")" + to_hex(tx_hash2) + R"(",
              "prefix_hash": ")" + to_hex(prefix_hash2) + R"(",
              "timestamp": 9000,
              "payment_id": ")" + to_hex(pid) + R"(",
              "fee": 105,
              "unlock_time": 5000,
              "height": 1961,
              "mixin": 16,
              "receives": [
                {
                  "amount": 566,
                  "public_key": ")" + to_hex(output_key.pub) + R"(",
                  "index": 0,
                  "id": {"legacy": {"amount": 0, "index": 2000}},
                  "tx_pub_key": ")" + to_hex(tx_key.pub) + R"(",
                  "rct": ")" + to_hex(ringct) + R"("
                },{
                  "amount": 655,
                  "public_key": ")" + to_hex(output_key2.pub) + R"(",
                  "index": 3,
                  "id": {"legacy": {"amount": 0, "index": 2001}},
                  "tx_pub_key": ")" + to_hex(tx_key2.pub) + R"(",
                  "rct": ")" + to_hex(ringct2) + R"("
                }
              ], "spends": [{
                "id": {"legacy": {"amount": 0, "index": 1000}},
                "key_image": ")" + to_hex(image) + R"("
              }]
            }
          ]
        })";

      const std::string error = R"({"msg": "e", "code": 5})";

      frame->requests = {
        {"/login", ""},
        {"/feed", ""},
        {"/feed", ""}
      };
      frame->responses = {
        R"({"new_address": true, "lookahead": {"maj_i": 50, "min_i": 200}})",
        boost::beast::http::status::not_implemented,
        boost::beast::http::status::switching_protocols
      };

      while (!frame->ws)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(!done);
      EXPECT(refreshed == 0);
      EXPECT(!wallet->feed_disabled);
      EXPECT(wallet->on_feed_fail);
      EXPECT(wallet->on_feed_refresh);
      EXPECT(frame->responses.size() == 0);
      EXPECT(result == std::error_code{});
      EXPECT(wallet->refresh_error == std::error_code{});
      EXPECT(wallet->lookahead_error == std::error_code{});
      EXPECT(wallet->subaddress_error == std::error_code{});
      EXPECT(wallet->import_error == std::error_code{});
      EXPECT(wallet->passed_login);

      lwsf_test::net::push::async_read(frame->ws, [&] (auto user) {
        login_verify(user.value());
        lwsf_test::net::push::async_pub(
          frame->ws, "tx_sync:" + to_msgpack(tx_sync), [&] (auto err) { EXPECT(!err); }
        );
      });

      while (!done)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(refreshed == 1);
      EXPECT(result == std::error_code{});
      EXPECT(ws_result == std::error_code{});
      EXPECT(wallet->on_feed_fail);
      EXPECT(wallet->on_feed_refresh);
      EXPECT(wallet->refresh_error == std::error_code{});
      EXPECT(wallet->lookahead_error == std::error_code{});
      EXPECT(wallet->subaddress_error == std::error_code{});
      EXPECT(wallet->import_error == std::error_code{});
      EXPECT(wallet->primary.restore_height == 900);
      EXPECT(wallet->primary.scan_height == 1950);
      EXPECT(wallet->primary.requested_start == 900);
      EXPECT(wallet->blockchain_height == 11000);
      EXPECT(wallet->primary.txes.size() == 2);
      EXPECT(wallet->primary.txes.count(tx_hash) == 1);
      {
        const auto tx = wallet->primary.txes.at(tx_hash);
        EXPECT(tx != nullptr);
        EXPECT(tx->spends.empty());
        EXPECT(tx->receives.size() == 1);
        EXPECT(tx->receives.count(output_key.pub) == 1);
        const auto& in = tx->receives.at(output_key.pub);
        EXPECT(in.global_index == 1000);
        EXPECT(in.amount == 1366);
        EXPECT(in.recipient == lwsf::internal::rpc::address_meta{});
        EXPECT(in.index == 0);
        EXPECT(bool(in.rct_mask));
        EXPECT(in.rct_mask.value_or(rct::key{}) == ringct);
        EXPECT(in.tx_pub == tx_key.pub);
        EXPECT(tx->transfers.empty());
        EXPECT(tx->description.empty());
        EXPECT(bool(tx->timestamp));
        EXPECT(tx->timestamp.value_or(std::chrono::system_clock::time_point{}) == std::chrono::system_clock::time_point{std::chrono::seconds{7000}});
        EXPECT(bool(tx->height));
        EXPECT(tx->height.value_or(0) == 1955);
        EXPECT(tx->amount == 1366);
        EXPECT(tx->fee == 103);
        EXPECT(tx->unlock_time == 4000);
        EXPECT(tx->direction == Monero::TransactionInfo::Direction_In);
        EXPECT(std::get_if<lwsf::internal::rpc::empty>(std::addressof(tx->payment_id)));
        EXPECT(tx->id == tx_hash);
        EXPECT(tx->prefix == prefix_hash);
        EXPECT(tx->coinbase == false);
        EXPECT(tx->failed == false);
      }
      {
        const auto tx = wallet->primary.txes.at(tx_hash2);
        EXPECT(tx != nullptr);
        EXPECT(tx->spends.size() == 1);
        EXPECT(tx->spends.count(image) == 1);
        const auto& out = tx->spends.at(image);
        EXPECT(out.amount == 1366);
        EXPECT(out.sender == lwsf::internal::rpc::address_meta{});
        EXPECT(out.tx_pub == tx_key.pub);
        EXPECT(out.output_pub == output_key.pub);
        EXPECT(tx->receives.size() == 2);
        EXPECT(tx->receives.count(output_key.pub) == 1);
        EXPECT(tx->receives.count(output_key2.pub) == 1);
        {
          const auto& in = tx->receives.at(output_key.pub);
          EXPECT(in.global_index == 2000);
          EXPECT(in.amount == 566);
          EXPECT(in.recipient == lwsf::internal::rpc::address_meta{});
          EXPECT(in.index == 0);
          EXPECT(bool(in.rct_mask));
          EXPECT(in.rct_mask.value_or(rct::key{}) == ringct);
          EXPECT(in.tx_pub == tx_key.pub);
        }
        {
          const auto& in = tx->receives.at(output_key2.pub);
          EXPECT(in.global_index == 2001);
          EXPECT(in.amount == 655);
          EXPECT(in.recipient == lwsf::internal::rpc::address_meta{});
          EXPECT(in.index == 3);
          EXPECT(bool(in.rct_mask));
          EXPECT(in.rct_mask.value_or(rct::key{}) == ringct2);
          EXPECT(in.tx_pub == tx_key2.pub);
        }
        EXPECT(tx->transfers.empty());
        EXPECT(tx->description.empty());
        EXPECT(bool(tx->timestamp));
        EXPECT(tx->timestamp.value_or(std::chrono::system_clock::time_point{}) == std::chrono::system_clock::time_point{std::chrono::seconds{9000}});
        EXPECT(bool(tx->height));
        EXPECT(tx->height.value_or(0) == 1961);
        EXPECT(tx->amount == 40);
        EXPECT(tx->fee == 105);
        EXPECT(tx->unlock_time == 5000);
        EXPECT(tx->direction == Monero::TransactionInfo::Direction_Out);
        EXPECT(std::get_if<crypto::hash8>(std::addressof(tx->payment_id)));
        EXPECT(std::get<crypto::hash8>(tx->payment_id) == pid);
        EXPECT(tx->id == tx_hash2);
        EXPECT(tx->prefix == prefix_hash2);
        EXPECT(tx->coinbase == false);
        EXPECT(tx->failed == false);
      }

      wallet->on_feed_refresh =
        [&] (auto err) { EXPECT(err == lwsf::error::feed); ++refreshed; };
      lwsf_test::net::push::async_pub(
        frame->ws, "error:" + to_msgpack(error), [&] (auto err) { EXPECT(!err); }
      );

      while (refreshed <= 1)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(refreshed == 2);
      EXPECT(result == std::error_code{});
      EXPECT(ws_result == std::error_code{});
      EXPECT(wallet->on_feed_fail);
      EXPECT(wallet->on_feed_refresh);
      EXPECT(wallet->refresh_error == std::error_code{});
      EXPECT(wallet->lookahead_error == std::error_code{});
      EXPECT(wallet->subaddress_error == std::error_code{});
      EXPECT(wallet->import_error == std::error_code{});
      EXPECT(wallet->primary.restore_height == 900);
      EXPECT(wallet->primary.scan_height == 1950);
      EXPECT(wallet->primary.requested_start == 900);
      EXPECT(wallet->blockchain_height == 11000);
      EXPECT(wallet->primary.txes.size() == 2);

      acceptor.async_accept(frame2->server, response_loop{frame2});
      frame2->requests = {{"/feed", ""}, {"/feed", ""}};
      frame2->responses = {
        boost::beast::http::status::not_implemented,
        boost::beast::http::status::switching_protocols
      };

      while (!frame2->ws)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(refreshed == 2);
      EXPECT(result == std::error_code{});
      EXPECT(ws_result == std::error_code{});
      EXPECT(wallet->on_feed_fail);
      EXPECT(wallet->on_feed_refresh);
      EXPECT(wallet->refresh_error == std::error_code{});
      EXPECT(wallet->lookahead_error == std::error_code{});
      EXPECT(wallet->subaddress_error == std::error_code{});
      EXPECT(wallet->import_error == std::error_code{});
      EXPECT(wallet->primary.restore_height == 900);
      EXPECT(wallet->primary.scan_height == 1950);
      EXPECT(wallet->primary.requested_start == 900);
      EXPECT(wallet->blockchain_height == 11000);
      EXPECT(wallet->primary.txes.size() == 2);
    }

    /*
     * Websocket Cleanup
     */

    std::shared_ptr<lwsf::internal::websocket::stream> ws;
    ws.swap(wallet->feed);
    if (ws)
    {
      const std::size_t refreshed_count = refreshed;
      wallet->on_feed_refresh = [&] (auto) { ++refreshed; };
      lwsf::internal::websocket::async_close(std::move(ws));
      lwsf_test::net::push::async_read(frame->ws, [] (auto) {});

      while (refreshed_count == refreshed)
      {
        io.restart();
        io.run_one();
      }
    }
  }
}

