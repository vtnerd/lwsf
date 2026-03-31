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

#include "websocket.h"

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/coroutine.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/multi_buffer.hpp>
#include <boost/beast/core/string_type.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <cstdint>
#include <utility>

#include "byte_slice.h"  // monero/contrib/epee/include
#include "byte_stream.h" // monero/contrib/epee/include
#include "error.h"
#include "lwsf_config.h"

namespace lwsf { namespace internal { namespace websocket
{
  using const_flat_buffer = boost::beast::net::const_buffer;

  struct read_loop
  {
    std::shared_ptr<stream> self_;
    std::function<update_func> receive_;
    void operator()(boost::system::error_code, std::size_t);
  };

  struct subscription : boost::asio::coroutine
  {
    std::shared_ptr<stream> self_;
    copyable_slice topic_;
    std::function<update_func> receive_;

    subscription(subscription&&) = default;
    subscription(const subscription&) = default;
    explicit subscription(std::shared_ptr<stream> self, epee::byte_slice&& topic, std::function<update_func>&& receive)
      : self_(std::move(self)), topic_(std::move(topic)), receive_(std::move(receive))
    {}

    void operator()(boost::system::error_code = {});
  };

  class stream
  { 
    std::vector<std::function<ping_func>> pings_;
    boost::asio::io_context::strand strand_;
    boost::asio::steady_timer timer_;
    boost::beast::multi_buffer buffer_;
    bool writing_;
    bool closing_;
    bool subscribed_;

    struct on_timeout
    {
      std::shared_ptr<stream> self_;
      void operator()(const boost::system::error_code error) const
      {
        LWSF_VERIFY(self_);
        if (!error || error != boost::asio::error::operation_aborted)
        {
          self_->notify_pings(boost::asio::error::operation_aborted);
          self_->async_close(self_);
        }
      }
    };

  protected:

    template<typename F>
    auto bind(F&& f) -> decltype(boost::asio::bind_executor(strand_, std::forward<F>(f)))
    { return boost::asio::bind_executor(strand_, std::forward<F>(f)); }
 
    template<typename T, typename F>
    void do_async_read(T& sock, F f)
    {
      sock.async_read(buffer_, bind(std::move(f)));
    }

    template<typename T, typename F>
    void do_async_write(T& sock, const const_flat_buffer buf, F f)
    {
      if (closing_)
        return f(boost::beast::websocket::error::closed);

      LWSF_VERIFY(f.self_);
      if (!writing_)
      {
        struct on_write
        {
          F f_;

          void operator()(const boost::system::error_code error, std::size_t)
          {
            const std::shared_ptr<stream> self = f_.self_;
            LWSF_VERIFY(self);

            self->timer_.cancel();
            self->writing_ = false;
            f_(error);
            if (error)
            {
              self->notify_pings(error);
              self->async_close(self);
            }
            else if (!self->pings_.empty())
              self->async_ping(on_ping{self});
          }
        };

        writing_ = true;
        timer_.expires_after(config::ping_timeout); // timeout for write not response
        timer_.async_wait(on_timeout{f.self_});
        sock.async_write(buf, bind(on_write{std::move(f)}));
      }
      else
        pings_.push_back(std::bind(&stream::async_write, f.self_, std::move(f)));
    }

    template<typename T, typename F>
    void do_async_ping(T& sock, F&& f)
    {
      if (closing_)
        return f(boost::beast::websocket::error::closed);

      LWSF_VERIFY(!writing_ && f.self_);
      writing_ = true;
      timer_.expires_after(config::ping_timeout);
      timer_.async_wait(on_timeout{f.self_});
      sock.async_ping(boost::beast::websocket::ping_data(), bind(std::forward<F>(f)));
    }

    template<typename T>
    void do_async_close(T& sock, std::shared_ptr<stream> self)
    {
      LWSF_VERIFY(self);
      if (!writing_)
      {
        const bool run = !closing_;
        closing_ = true;
        if (run)
          sock.async_close(boost::beast::websocket::close_reason(), bind(std::bind(&stream::async_shutdown, self, self)));
      }
      else
        pings_.push_back(std::bind(&stream::async_close, self, self));
    }

    void do_async_shutdown(tcp_sock& sock, std::shared_ptr<stream>)
    { do_cleanup(sock); }

    void do_async_shutdown(boost::asio::ssl::stream<tcp_sock>& sock, std::shared_ptr<stream> self)
    {
      LWSF_VERIFY(self);
      sock.async_shutdown(bind(std::bind(&stream::cleanup, self)));
    }

    void do_cleanup(tcp_sock& sock)
    {
      boost::system::error_code ec{};
      sock.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
      sock.close(ec);
    }

    void do_cleanup(boost::asio::ssl::stream<tcp_sock>& sock)
    { do_cleanup(sock.next_layer()); }

  public:
    explicit stream(boost::asio::io_context& io)
      : strand_(io), timer_(io), buffer_(), writing_(false), closing_(false), subscribed_(false)
    {}

    //! \return True if this function has never been invoked previously
    bool subscribe() noexcept
    {
      const bool rc = !subscribed_;
      subscribed_ = true;
      return rc;
    }

    template<typename F>
    void dispatch(F&& f)
    {
      boost::asio::dispatch(strand_, std::forward<F>(f));
    }

    epee::byte_slice gather_buffer()
    {
      epee::byte_stream sink{};
      sink.reserve(buffer_.size());

      const auto buffers = buffer_.cdata();
      const auto end = boost::asio::buffer_sequence_end(buffers);
      for (auto cur = boost::asio::buffer_sequence_begin(buffers); cur != end; ++cur)
      {
        const const_flat_buffer this_buf = *cur;
        sink.write(reinterpret_cast<const std::uint8_t*>(this_buf.data()), this_buf.size());
      }

      buffer_.consume(buffer_.size());
      return epee::byte_slice{std::move(sink)};
    }

    struct on_ping
    {
      std::shared_ptr<stream> self_;
      void operator()(const boost::system::error_code& error)
      {
        LWSF_VERIFY(self_);
        self_->writing_ = false;
        if (self_->timer_.cancel() || error)
        {
          self_->notify_pings(error);
          if (error)
            self_->async_close(self_);
        }
      }
    };

    void notify_pings(const boost::system::error_code error = {})
    {
      std::vector<std::function<ping_func>> pings;
      pings.swap(pings_);
      for (const auto& ping : pings)
        ping(error);
    }

    bool add_ping_notifier(std::function<ping_func>&& notifier)
    {
      pings_.push_back(std::move(notifier));
      return !writing_;
    }

    virtual void async_read(read_loop&&) = 0;
    virtual void async_write(subscription) = 0;
    virtual void async_ping(on_ping&&) = 0;
    virtual void async_close(std::shared_ptr<stream>) = 0;
    virtual void async_shutdown(std::shared_ptr<stream>) = 0;
    virtual void cleanup() = 0;
  };

  template<typename T>
  class stream_ final : public stream
  {
    boost::beast::websocket::stream<T> sock_;

  public:
    explicit stream_(T&& sock, boost::asio::io_context& io)
      : stream(io), sock_(std::move(sock))
    {
      sock_.binary(true);
    }

    template<typename F>
    void async_handshake(const std::string& host, const std::string& target, std::string&& protocol, F f)
    {
      namespace http = boost::beast::http;
      struct on_control
      {
        std::weak_ptr<stream> self_;
        void operator()(boost::beast::websocket::frame_type, boost::beast::string_view)
        {
          const auto self = self_.lock();
          if (self)
            self->notify_pings();
        }
      };

      LWSF_VERIFY(f.self_);
      sock_.control_callback(on_control{f.self_});
      sock_.set_option(
        boost::beast::websocket::stream_base::decorator(
          [protocol = std::move(protocol)] (http::request_header<>& hdr)
          { hdr.set(http::field::sec_websocket_protocol, protocol); }
        )
      );
      sock_.async_handshake(host, target, bind(std::move(f)));
    }

    virtual void async_read(read_loop&& handler) override final
    { do_async_read(sock_, std::move(handler)); }

    virtual void async_write(subscription handler) override final
    {
      std::uint8_t const* const data = handler.topic_.data.data();
      const std::size_t size = handler.topic_.data.size();
      do_async_write(sock_, const_flat_buffer(data, size), std::move(handler));
    }

    virtual void async_ping(on_ping&& handler) override final
    { do_async_ping(sock_, std::move(handler)); }

    virtual void async_close(std::shared_ptr<stream> self) override final
    { do_async_close(sock_, std::move(self)); }

    virtual void async_shutdown(std::shared_ptr<stream> self) override final
    { do_async_shutdown(sock_.next_layer(), std::move(self)); }

    virtual void cleanup() override final
    { do_cleanup(sock_.next_layer()); }
  };

  struct after_connect
  {
    std::shared_ptr<stream> self_;
    std::function<ready_func> notifier_;

    void operator()(const boost::system::error_code error)
    {
      LWSF_VERIFY(notifier_);
      if (error)
        notifier_(error, nullptr);
      else
        notifier_(error, self_);
    }
  };

  void read_loop::operator()(const boost::system::error_code error, std::size_t)
  {
    LWSF_VERIFY(self_ && receive_);
    stream& self = *self_;
    receive_(error, self.gather_buffer());
    if (!error)
      self.async_read(std::move(*this));
    else
      self.async_close(self_);
  }

  void subscription::operator()(boost::system::error_code error)
  {
    LWSF_VERIFY(self_ && receive_);
    stream& self = *self_;
    BOOST_ASIO_CORO_REENTER(*this)
    {
      if (self.subscribe())
        BOOST_ASIO_CORO_YIELD self.async_write(std::move(*this));
      else
        error = boost::asio::error::already_started;

      if (error)
      {
        receive_(error, epee::byte_slice{});
        self.async_close(std::move(self_));
      }
      else
        self.async_read(read_loop{std::move(self_), std::move(receive_)});
    }
  }

  template<typename T>
  inline void do_start(std::shared_ptr<stream_<T>> self, const std::string& host, const std::string& target, std::string&& protocol, std::function<ready_func>&& notifier)
  {
    self->async_handshake(host, target, std::move(protocol), after_connect{self, std::move(notifier)});
  }

  void async_start(tcp_sock&& sock, boost::asio::io_context& io, std::string&& host, std::string&& target, std::string&& protocol, std::function<ready_func>&& notifier)
  {
    do_start(std::make_shared<stream_<tcp_sock>>(std::move(sock), io), host, target, std::move(protocol), std::move(notifier));
  }
  
  void async_start(boost::asio::ssl::stream<tcp_sock>&& sock, boost::asio::io_context& io, std::string&& host, std::string&& target, std::string&& protocol, std::function<ready_func>&& notifier)
  {
    do_start(std::make_shared<stream_<boost::asio::ssl::stream<tcp_sock>>>(std::move(sock), io), host, target, std::move(protocol), std::move(notifier));
  }

  void async_subscribe(std::shared_ptr<stream> self, epee::byte_slice&& topic, std::function<update_func>&& receive)
  { 
    LWSF_VERIFY(self);
    self->dispatch(subscription{self, std::move(topic), std::move(receive)});
  }

  void async_ping(std::shared_ptr<stream> self, std::function<ping_func>&& notifier)
  {
    LWSF_VERIFY(self);
    self->dispatch([self, notifier = std::move(notifier)] () mutable {
      if(self->add_ping_notifier(std::move(notifier)))
        self->async_ping(stream::on_ping{self});
    });
  }

  void async_close(std::shared_ptr<stream> self)
  {
    LWSF_VERIFY(self);
    self->dispatch(std::bind(&stream::async_close, self, self));
  }
}}} // lwsf // internal // websocket
