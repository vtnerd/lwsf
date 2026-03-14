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

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <string>
#include "common/error.h" // monero/src
#include "net/http.h"

using client_request =
  boost::beast::http::request<boost::beast::http::string_body>;

namespace
{
  void get_next(boost::asio::io_context& io, boost::asio::ip::tcp::socket& server, boost::beast::flat_buffer& buffer, client_request& req)
  {
    bool ready = false;
    boost::beast::http::async_read(server, buffer, req, [&] (auto, auto) { ready = true; });

    while (!ready)
    {
      io.restart();
      io.run_one();
    }
  }

  epee::byte_slice to_slice(std::string src)
  {
    return epee::byte_slice{std::move(src)};
  }

  std::string to_string(const epee::byte_slice& src)
  {
    return {reinterpret_cast<const char*>(src.data()), src.size()};
  }

  void send(boost::asio::ip::tcp::socket& server, std::string body)
  {
    boost::beast::http::response<boost::beast::http::string_body> resp;
    resp.body() = std::move(body);
    resp.prepare_payload();
    boost::beast::http::write(server, resp); 
  }
}

LWS_CASE("net::http")
{
  using tcp = boost::asio::ip::tcp;

  SETUP("client+server")
  {
    boost::asio::io_context io{};
    tcp::socket server{io};
    tcp::acceptor acceptor{io, tcp::endpoint(tcp::v4(), 0)};
    acceptor.listen();

    boost::beast::flat_buffer buffer{};
    lwsf::internal::http::client client{};
    {
      std::error_code actual;
      client.get_async("/foo", [&] (std::error_code error, auto) { actual = error; });
      EXPECT(actual == common_error::kInvalidArgument);
    }
    {
      const auto endpoint = acceptor.local_endpoint();
      client.init(io, "127.0.0.1", "lws", endpoint.port(), epee::net_utils::ssl_support_t::e_ssl_support_disabled); 
    
      EXPECT(!client.is_connected());

      bool client_ready = false;
      bool server_ready = false;
      client.get_async("/foo", [&] (auto, auto) { client_ready = true; });
      acceptor.async_accept(server, [&] (auto) { server_ready = true; });

      EXPECT(!client.is_connected());
      while (!server_ready)
      {
        io.restart();
        io.run_one();
      }

      client_request request{};
      get_next(io, server, buffer, request);
      EXPECT(request.method() == boost::beast::http::verb::get);
      EXPECT(request.body().empty());
      EXPECT(request.target() == "lws/foo");

      send(server, "");

      EXPECT(!client_ready);
      while (!client_ready)
      {
        io.restart();
        io.run_one();
      }

      EXPECT(client.is_connected());
    } // end temp setup variables 

    SECTION("post")
    {
      const std::string request_body = "THE REQUEST";
      const std::string response = "THE RESPONSE";

      epee::byte_slice actual;
      client.post_async("/posted", to_slice(request_body), [&] (auto, epee::byte_slice src) { actual = std::move(src); });

      client_request request{};
      get_next(io, server, buffer, request);
      EXPECT(request.method() == boost::beast::http::verb::post);
      EXPECT(request.body() == request_body);
      EXPECT(request.target() == "lws/posted");

      send(server, response);

      while (actual.empty())
      {
        io.restart();
        io.run_one();
      }
      
      EXPECT(to_string(actual) == response);
    }
  
    SECTION("post/get x3")
    {
      using verb = boost::beast::http::verb;
      const std::array<verb, 3> verbs{{verb::post, verb::get, verb::post}};
      const std::array<std::string, 3> targets{{"/post1", "/get1", "/post2"}};
      const std::array<std::string, 3> requests{{"REQ1", "", "REQ3"}};
      const std::array<std::string, 3> responses{{"RESP1", "RESP2", "RESP3"}};
      std::array<epee::byte_slice, 3> actuals;

      client.post_async(targets[0], to_slice(requests[0]), [&] (auto, epee::byte_slice src) { actuals[0] = std::move(src); });
      client.get_async(targets[1], [&] (auto, epee::byte_slice src) { actuals[1] = std::move(src); });
      client.post_async(targets[2], to_slice(requests[2]), [&] (auto, epee::byte_slice src) { actuals[2] = std::move(src); });

      for (std::size_t i = 0; i < requests.size(); ++i)
      {
        client_request request{};
        get_next(io, server, buffer, request);
        EXPECT(request.method() == verbs[i]);
        EXPECT(request.body() == requests[i]);
        EXPECT(request.target() == "lws" + targets[i]);

        send(server, responses[i]);
      }

      while (actuals[2].empty())
      {
        io.restart();
        io.run_one();
      }
     
      for (std::size_t i = 0; i < actuals.size(); ++i)
        EXPECT(to_string(actuals[i]) == responses[i]);
    }

    SECTION("invalid host")
    {
      std::error_code actual;
      client.init(io, ".test", "", 80, epee::net_utils::ssl_support_t::e_ssl_support_disabled);
      client.get_async("/", [&] (std::error_code error, auto) { actual = error; });

      while (actual == std::error_code{})
      {
        io.restart();
        io.run_one();
      }

      EXPECT(actual == boost::system::error_code{boost::asio::error::host_not_found});
    }

    SECTION("connect timeout")
    {
      std::error_code actual;
      tcp::acceptor acceptor{io, tcp::endpoint(tcp::v4(), 0)};
      acceptor.listen();

      client.init(io, "127.0.0.1", "", acceptor.local_endpoint().port(), epee::net_utils::ssl_support_t::e_ssl_support_disabled);
      client.get_async("/", [&] (std::error_code error, auto) { actual = error; });

      io.restart();
      io.run();

      EXPECT(actual == boost::system::error_code{boost::asio::error::operation_aborted});
    }

    SECTION("response timeout")
    {
      std::error_code actual;
      client.get_async("/get", [&] (std::error_code error, auto) { actual = error; });

      io.restart();
      io.run();

      EXPECT(actual == boost::system::error_code{boost::asio::error::operation_aborted});
    }
  } // SETUP
}
