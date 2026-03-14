// Copyright (c) 2024, The Monero Project
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

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/system/error_code.hpp>
#include <boost/thread/mutex.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include "byte_slice.h"    // monero/contrib/epee/include
#include "net/net_ssl.h"   // monero/contrib/epee/include

namespace lwsf { namespace internal { namespace http
{
  enum class error : int
  {
    none = 0, invalid_code = -1 /* Otherwise HTTP error code */
  };

  const std::error_category& error_category() noexcept;
  inline std::error_code make_error_code(const error value) noexcept
  {
    return std::error_code{int(value), error_category()};
  }

  struct client_state;
  using server_response_func = void(std::error_code, epee::byte_slice);
  using callback_func = void(boost::system::error_code);
  using connect_func = void(std::shared_ptr<client_state>, std::function<callback_func>);

  //! Primarily for webhooks, where the response is (basically) ignored.
  class client
  {
    
    std::shared_ptr<client_state> state_;
    std::function<connect_func> proxy_;
    mutable boost::mutex sync_;

    void queue_async(std::string&& target, epee::byte_slice&& body, std::function<server_response_func>&& notifier, boost::beast::http::verb verb) const;

  public:
    struct direct
    {
      void operator()(std::shared_ptr<client_state>, std::function<callback_func>) const;
    };

    struct socks
    {
      boost::asio::ip::tcp::endpoint proxy_address;
      void operator()(std::shared_ptr<client_state>, std::function<callback_func>) const;
    };

    client()
      : state_(nullptr), proxy_(direct{}), sync_()
    {}

    void init(boost::asio::io_context& io, std::string host, std::string prefix, std::uint16_t port, epee::net_utils::ssl_options_t ssl);
  
    client(client&&) = delete;
    client(const client&) = delete;
    ~client();
    client& operator=(client&&) = delete; 
    client& operator=(const client&) = delete;

    void shutdown(); // break accidental memory cycles

    //! thread-safe
    bool is_connected() const noexcept;

    //! thread-safe
    void set_proxy(std::function<connect_func> connector);

    //! Never blocks. Thread safe. \return `success()` if `url` is valid.
    void post_async(std::string target, epee::byte_slice body, std::function<server_response_func> notifier) const;

    /*! Never blocks. Thread safe. Calls `notifier` with server response iff
      `success()` is returned.
      \return `success()` if `url` is valid. */
    void get_async(std::string target, std::function<server_response_func> notifier) const;
  };
}}} // lwsf // internal // http

namespace std
{
  template<>
  struct is_error_code_enum<lwsf::internal::http::error>
    : true_type
  {};
}
