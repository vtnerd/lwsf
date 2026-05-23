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

#include "push.test.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <deque>
#include <functional>
#include <string>
#include <utility>

#include "error.h"

namespace lwsf_test { namespace net { namespace push
{
  struct connection
  {
    boost::beast::websocket::stream<socket> ws_;
    boost::asio::io_context::strand strand_;
    std::deque<std::pair<std::string, std ::function<pub>>> msgs_;
    boost::beast::flat_buffer buffer_;

    connection(socket&& sock)
      : ws_(std::move(sock)), strand_(ws_.next_layer().get_executor().context()), msgs_(), buffer_()
    {
      ws_.binary(true);
    }

    template<typename F>
    auto bind(F&& f) -> decltype(boost::asio::bind_executor(strand_, std::forward<F>(f)))
    {
      return boost::asio::bind_executor(strand_, std::forward<F>(f));
    }
  };

  namespace
  {
    struct on_read
    {
      std::shared_ptr<connection> self_;
      std::function<sub> read_;
      void operator()(const boost::system::error_code error, std::size_t)
      {
        LWSF_VERIFY(self_ && read_);
        if (!error)
        {
          const auto buf = self_->buffer_.data();
          std::string out{reinterpret_cast<const char*>(buf.data()), buf.size()};
          self_->buffer_.consume(buf.size());
          read_(std::move(out));
        }
        else
          read_(std::error_code{error});
      }
    };

    struct on_write
    {
      std::shared_ptr<connection> self_;
      void operator()(const boost::system::error_code error, std::size_t = {})
      {
        LWSF_VERIFY(self_ && !self_->msgs_.empty());

        std::pair<std::string, std::function<pub>> msg;
        msg.swap(self_->msgs_.front());
        self_->msgs_.pop_front();

        if (!self_->msgs_.empty())
          start(std::move(self_));

        if (msg.second)
          msg.second(error);
      }

      static void start(std::shared_ptr<connection> self)
      {
        LWSF_VERIFY(self && !self->msgs_.empty());
        const std::string& msg = self->msgs_.front().first;
        self->ws_.async_write(boost::asio::buffer(msg.data(), msg.size()), self->bind(on_write{self}));
      }
    };
  }

  void async_handshake(socket&& sock, const request& req, std::function<ready> done)
  {
    auto self = std::make_shared<connection>(std::move(sock));
    self->ws_.async_accept(req, self->bind([self, done = std::move(done)] (auto error) {
      if (error)
        done(std::error_code{error});
      else
        done(self);
    }));
  }

  void async_read(std::shared_ptr<connection> self, std::function<sub> read)
  {
    LWSF_VERIFY(self);
    boost::asio::dispatch(self->strand_, [self, read = std::move(read)] () mutable {
      self->ws_.async_read(self->buffer_, self->bind(on_read{self, std::move(read)}));
    });
  }

  void async_pub(std::shared_ptr<connection> self, std::string msg, std::function<pub> sent)
  {
    LWSF_VERIFY(self);
    boost::asio::dispatch(self->strand_, [self, msg = std::move(msg), sent = std::move(sent)] () mutable {
      const bool empty = self->msgs_.empty();
      self->msgs_.push_back({std::move(msg), std::move(sent)});
      if (empty)
        on_write::start(std::move(self));
    });
  }

  void async_close(std::shared_ptr<connection> self)
  {
    LWSF_VERIFY(self);
    boost::asio::dispatch(self->strand_, [self] {
      self->ws_.async_close(boost::beast::websocket::close_reason(), [] (auto) {});
    });
  }
}}} // lwsf_test // net // push
