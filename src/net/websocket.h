// Copyright (c) 2026, The Monero Project
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
#include <boost/asio/ssl.hpp>
#include <functional>
#include <memory>
#include <string>
#include <system_error>

#include "byte_slice.h" // monero/contrib/epee/include

namespace lwsf { namespace internal
{

  struct copyable_slice
  {
    copyable_slice() noexcept
      : data(nullptr)
    {}

    copyable_slice(epee::byte_slice&& data) noexcept
      : data(std::move(data))
    {}

    copyable_slice(copyable_slice&&) noexcept = default;
    copyable_slice(const copyable_slice& rhs) noexcept
      : data(rhs.data.clone())
    {}

    epee::byte_slice data;
  };

  namespace websocket  
  { 
    class stream;
    using tcp_sock = boost::asio::ip::tcp::socket;
    using ready_func = void(std::error_code, std::shared_ptr<stream>);
    using update_func = void(std::error_code, copyable_slice);
    using ping_func = void(std::error_code);

    void async_start(tcp_sock&& sock, boost::asio::io_context& io, std::string&& host, std::string&& target, std::string&& protocol, std::function<ready_func>&& notifier);
    void async_start(boost::asio::ssl::stream<tcp_sock>&& sock, boost::asio::io_context& io, std::string&& host, std::string&& target, std::string&& protocol, std::function<ready_func>&& notifier);

    /*! Subscribe to `topic` and call `notifier` on each incoming message. Can
      only invoke once. Thread-safe.
      \param topic The raw message to be sent to server
      \param notifier Called on every received message.
      \throw std::invalid_argument if invoked multiple times. */
    void async_subscribe(std::shared_ptr<stream> self, epee::byte_slice&& topic, std::function<update_func>&& notifier);

    //! Ping the server at any time. Multiple calls allowed. Thread safe.
    void async_ping(std::shared_ptr<stream> self, std::function<ping_func>&& notifier);

    //! Terminate the stream gracefully
    void async_close(std::shared_ptr<stream> self);
  } // websocket
}} // lwsf // internal
