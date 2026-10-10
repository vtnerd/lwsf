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

#include "http.h"

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/coroutine.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core/flat_static_buffer.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/beast/version.hpp>
#include <boost/optional/optional.hpp>
#include <boost/thread/locks.hpp>
#include <cstdint>
#include <deque>
#include <limits>
#include <ostream>

#include "byte_stream.h"  // monero/controib/epee/include
#include "common/error.h" // monero/src
#include "error.h"
#include "lwsf_config.h"
#include "misc_log_ex.h"  // monero/contrib/epee/include
#include "net/net_utils_base.h"
#include "net/socks.h"    // monero/src
#include "net/websocket.h"
#include "string_tools.h" // monero/contrib/epee/include

namespace lwsf { namespace internal { namespace http
{
  namespace
  {
    const char* get_string(error value) noexcept
    {
      switch (value)
      {
      default:
        break;

      case error::none:
        return "No rpc errors";
      case error::invalid_code:
        return "Invalid status code from HTTP server";
      }
      return nullptr;
    }

    struct message
    {
      message(epee::byte_slice body, std::string target, std::function<server_response_func>&& notifier, boost::beast::http::verb verb)
        : body(std::move(body)),
          notifier(std::move(notifier)),
          target(std::move(target)),
          verb(verb)
      {}

      message(message&&) = default;
      message(const message& rhs)
        : body(rhs.body.clone()),
          notifier(rhs.notifier),
          target(rhs.target),
          verb(rhs.verb)
      {}

      bool is_get() const noexcept { return verb == boost::beast::http::verb::get; }

      epee::byte_slice body;
      std::function<server_response_func> notifier;
      std::string target;
      boost::beast::http::verb verb;
    };

    std::ostream& operator<<(std::ostream& out, const message& src)
    {
      out << src.target;
      return out;
    }

    struct stream_body
    {
      using value_type = epee::byte_stream;
 
      struct reader
      {
        epee::byte_stream& body_;

        template<bool isRequest, class Fields>
        reader(boost::beast::http::header<isRequest, Fields>&, value_type& body)
          : body_(body)
        {}

        void init(boost::optional<std::uint64_t> const& content_length, boost::system::error_code& ec)
        {
          if (content_length)
          {
            // size_t is 32-bit on some targets (armv7): a Content-Length that
            // can't fit is not a body we could hold, so reject it rather than
            // truncate the reserve.
            if constexpr (std::numeric_limits<std::uint64_t>::max() > std::numeric_limits<std::size_t>::max())
            {
              if (*content_length > std::numeric_limits<std::size_t>::max())
              {
                ec = boost::beast::http::error::body_limit;
                return;
              }
            }
            body_.reserve(static_cast<std::size_t>(*content_length));
          }
          ec = {};
        }

        template<class ConstBufferSequence>
        std::size_t put(ConstBufferSequence const& buffers, boost::system::error_code& ec)
        {
          const std::size_t size = boost::asio::buffer_size(buffers);
          body_.write({reinterpret_cast<const std::uint8_t*>(buffers.data()), size});
          ec = {};
          return size;
        }

        void finish(boost::system::error_code& ec)
        {
          ec = {};
        }
      };
    };

    struct slice_body
    {
      using value_type = epee::byte_slice;

      static std::size_t size(const value_type& source) noexcept
      {
        return source.size();
      };

      struct writer
      {
        epee::byte_slice body_;

        using const_buffers_type = boost::asio::const_buffer;

        template<bool is_request, typename Fields>
        explicit writer(boost::beast::http::header<is_request, Fields> const&, value_type const& body)
          : body_(body.clone())
        {}

        void init(boost::beast::error_code& ec)
        {
          ec = {};
        }

        boost::optional<std::pair<const_buffers_type, bool>> get(boost::beast::error_code& ec)
        {
          ec = {};
          return {{const_buffers_type{body_.data(), body_.size()}, false}};
        }
      };
    };
  } // anonymous

  //! \return Category for `error`.
  const std::error_category& error_category() noexcept
  {
    struct category final : std::error_category
    {
      virtual const char* name() const noexcept override final
      {
        return "lwsf::internal::http::error_category()";
      }

      virtual std::string message(int value) const override final
      {
        char const * const msg = get_string(error(value));
        if (msg)
          return msg;
        return "HTTP error code " + std::to_string(value);
      }
    };
    static const category instance{};
    return instance;
  }

  struct client_state
  {
    using connect_func =
      void(std::shared_ptr<client_state>, std::function<void(boost::system::error_code)>);

    boost::beast::flat_static_buffer<config::http_parser_buffer_size> buffer;
    const std::function<connect_func> connect;
    std::deque<message> outgoing;
    const std::string host;
    const std::string prefix;
    boost::asio::steady_timer timer;
    boost::asio::io_context::strand strand;
    boost::asio::ip::tcp::endpoint endpoint;
    boost::beast::http::request<slice_body> request;
    const epee::net_utils::ssl_options_t ssl;
    boost::asio::ssl::context ssl_context;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> sock;
    boost::optional<boost::beast::http::parser<false, stream_body>> parser;
    std::size_t iteration;
    const std::uint16_t port;
    std::atomic<bool> is_connected;
    epee::net_utils::ssl_support_t ssl_status;
    bool retry; //! in case of connection timeouts, etc

    client_state(boost::asio::io_context& io, std::string host, std::string prefix, const std::uint16_t port, epee::net_utils::ssl_options_t in, std::function<connect_func> connect)
      : buffer{},
        connect(std::move(connect)),
        outgoing(),
        host(std::move(host)),
        prefix(std::move(prefix)),
        timer(io),
        strand(io),
        endpoint(),
        request{},
        ssl(std::move(in)),
        ssl_context(ssl.create_context()),
        sock(io, ssl_context),
        parser(),
        iteration(0),
        port(port),
        is_connected(false),
        ssl_status(ssl.support),
        retry(true)
    {}

    template<typename F>
    void async_write(F&& callback)
    {
      assert(!outgoing.empty());
      const bool no_body = outgoing.front().body.empty();
      if (!prefix.empty())
        outgoing.front().target.insert(0, prefix.data(), prefix.size());

      request = {
        outgoing.front().verb,
        outgoing.front().target,
        config::http_version,
        outgoing.front().body.clone()
      };
      request.set(boost::beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
      if (!no_body)
        request.set(boost::beast::http::field::content_type, "application/json");

      // Setting Host is tricky. Check for v6 and non-standard ports
      boost::system::error_code error{};
      boost::asio::ip::make_address_v6(host, error);
      const bool https = ssl_status == epee::net_utils::ssl_support_t::e_ssl_support_enabled;
      if (!error)
        request.set(boost::beast::http::field::host, "[" + host + "]:" + std::to_string(port));
      else if ((https && port == 443) || (!https && port == 80))
        request.set(boost::beast::http::field::host, host);
      else
        request.set(boost::beast::http::field::host, host + ":" + std::to_string(port));

      request.prepare_payload();
      if (https)
        boost::beast::http::async_write(sock, request, boost::asio::bind_executor(strand, std::forward<F>(callback)));
      else
        boost::beast::http::async_write(sock.next_layer(), request, boost::asio::bind_executor(strand, std::forward<F>(callback)));
    }

    template<typename F>
    void async_read(F&& callback)
    {
      assert(sock);
      assert(!outgoing.empty());
      parser.emplace();
      parser->body_limit(config::http_body_limit);
      if (ssl_status == epee::net_utils::ssl_support_t::e_ssl_support_enabled)
        boost::beast::http::async_read(sock, buffer, *parser, boost::asio::bind_executor(strand, std::forward<F>(callback)));
      else
        boost::beast::http::async_read(sock.next_layer(), buffer, *parser, boost::asio::bind_executor(strand, std::forward<F>(callback)));
    }

    void close()
    {
      MWARNING("Closing socket to " << host);

      ++iteration;
      is_connected = false;

      boost::system::error_code ignore{};
      timer.cancel();
      sock.next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignore);
      sock.next_layer().close(ignore);
    }

    void notify_connection_error(const boost::system::error_code error)
    {
      for (auto& elem : outgoing)
      {
        if (elem.notifier)
          elem.notifier(error, {});
      }

      outgoing.clear();
      close();
    }
  };  

  namespace
  {
    template<typename F>
    void set_timeout(std::shared_ptr<client_state> self, const std::chrono::steady_clock::duration timeout, F f)
    {
      LWSF_VERIFY(self);

      struct on_timeout
      {
        on_timeout() = delete;
        std::shared_ptr<client_state> self_;
        F f_;
        const std::size_t iteration;

        void operator()(const boost::system::error_code error)
        {
          LWSF_VERIFY(self_);
          if (!self_ || error == boost::asio::error::operation_aborted)
            return;
          if (iteration < self_->iteration)
            return;

          MWARNING("Timeout in HTTP attempt to " << self_->host);
          f_(error);
        }
      };

      client_state& me = *self;
      me.timer.expires_after(timeout);
      me.timer.async_wait(boost::asio::bind_executor(me.strand, on_timeout{std::move(self), std::move(f), me.iteration}));
    }

    void set_timeout(std::shared_ptr<client_state> self, const std::chrono::steady_clock::duration timeout)
    {
      LWSF_VERIFY(self);

      struct on_timeout
      {
        on_timeout() = delete;
        std::shared_ptr<client_state> self_;

        void operator()(boost::system::error_code error = {}) const
        {
          LWSF_VERIFY(self_);
          assert(self_->strand.running_in_this_thread());
          self_->close();
        }
      };
      
      set_timeout(self, timeout, on_timeout{self});
    }

    class client_loop : public boost::asio::coroutine
    {
      std::shared_ptr<client_state> self_;

    public:
      explicit client_loop(std::shared_ptr<client_state> self) noexcept
        : boost::asio::coroutine(), self_(std::move(self))
      {}

      void operator()(boost::system::error_code error = {}, std::size_t = 0)
      {
        LWSF_VERIFY(self_);

        client_state& self = *self_;
        assert(self.strand.running_in_this_thread());
        BOOST_ASIO_CORO_REENTER(*this)
        {
          if (!self.is_connected)
          {
  do_connect:
            BOOST_ASIO_CORO_YIELD self.connect(self_, *this);

            if (!error && self.ssl_status != epee::net_utils::ssl_support_t::e_ssl_support_disabled)
            {
              ++self.iteration;
              set_timeout(self_, config::connect_timeout); // socks needs a reset
              self.ssl.configure(self.sock, boost::asio::ssl::stream_base::client, self.host);

              MDEBUG("Starting SSL handshake to " << self.host << " for HTTP");
              BOOST_ASIO_CORO_YIELD self.sock.async_handshake(
                boost::asio::ssl::stream<boost::asio::ip::tcp::socket>::client,
                  boost::asio::bind_executor(self.strand, std::move(*this))
              );

              if (error)
              {
                MERROR("SSL handshake to " << self.host << " failed: " << error.message());
                if (self.ssl_status == epee::net_utils::ssl_support_t::e_ssl_support_autodetect)
                {
                  MINFO("Retrying to << " << self.host << " without ssl (autodetect mode)");
                  self.ssl_status = epee::net_utils::ssl_support_t::e_ssl_support_disabled;
                  error = {};
                  ++self.iteration;
                  goto do_connect;
                }
              }
              else
                self.ssl_status = epee::net_utils::ssl_support_t::e_ssl_support_enabled;
            }
          }

          if (error)
            return self.notify_connection_error(error);

          ++self.iteration;
          self.is_connected = true;
          while (!self.outgoing.empty())
          {
            if (self.outgoing.front().verb == boost::beast::http::verb::subscribe)
            {
              std::function<server_response_func> notifier;
              notifier.swap(self.outgoing.front().notifier);
              self.outgoing.clear();
              return notifier({}, {});
            }

            set_timeout(self_, config::rpc_timeout);

            MDEBUG("Sending " << self.outgoing.front().body.size() << " bytes in HTTP " << (self.outgoing.front().is_get() ? "GET" : "POST") << " to " << self.outgoing.front());
            BOOST_ASIO_CORO_YIELD self.async_write(std::move(*this));

            if (!error)
            {
              MDEBUG("Starting read from " << self.outgoing.front() << " to previous HTTP message");
              BOOST_ASIO_CORO_YIELD self.async_read(std::move(*this));
                    
              if (error)
                MERROR("Failed to parse HTTP response from " << self.outgoing.front() << ": " << error.message());
              else if (self.parser->get().result_int() != 200 && self.parser->get().result_int() != 201)
              {
                const auto result = self.parser->get().result_int();
                MERROR(self.outgoing.front() << " returned " << result << " status code");
                if (0 < result && result <= std::numeric_limits<int>::max())
                  self.outgoing.front().notifier(http::error(result), epee::byte_slice{});
                else
                  self.outgoing.front().notifier(http::error::invalid_code, epee::byte_slice{});
              }
              else
              {
                MDEBUG(self.outgoing.front() << " successful");
                if (self.outgoing.front().notifier)
                  self.outgoing.front().notifier({}, epee::byte_slice{std::move(self.parser->get()).body()});
               }
             }
             else
              MERROR("Failed HTTP " << (self.outgoing.front().is_get() ? "GET" : "POST") << " to " << self.outgoing.front() << ": " << error.message());

            // if write, read, or parse errors
            if (error)
            {
              if (!self.retry)
                return self.notify_connection_error(error);
              self.retry = false;
              self.close();
              return client_loop{self_}(); // possible timeout; connect retry
            }

            self.outgoing.pop_front();
            ++self.iteration;
            self.retry = true;

            if (!self.parser->get().keep_alive())
            {
              self.close();
              if (!self.outgoing.empty())
                return client_loop{self_}();
            }
          }
        }
      }
    };

    void queue_async_(std::shared_ptr<client_state> state, std::string&& target, epee::byte_slice&& body, std::function<server_response_func>&& notifier, boost::beast::http::verb verb)
    {
      message msg{std::move(body), std::move(target), std::move(notifier), verb};
      if (!state)
        return msg.notifier(common_error::kInvalidArgument, epee::byte_slice{});

      MDEBUG("Queueing HTTP " << to_string(verb) << " to " << msg << " using " << state.get());
      boost::asio::dispatch(
        state->strand,
        [state, msg = std::move(msg)] () mutable
        {
          const bool empty = state->outgoing.empty();
          state->outgoing.push_back(std::move(msg));
          if (empty)
            boost::asio::post(state->strand, client_loop{state});
        }
      );
    }
  } // anonymous

  void client::queue_async(std::string&& target, epee::byte_slice&& body, std::function<server_response_func>&& notifier, boost::beast::http::verb verb) const
  {
    std::shared_ptr<client_state> state;
    {
      const boost::lock_guard<boost::mutex> lock{sync_};
      state = state_;
    }
    queue_async_(std::move(state), std::move(target), std::move(body), std::move(notifier), verb);
  }

  void client::direct::operator()(std::shared_ptr<client_state> self, std::function<callback_func> f) const
  {
    struct frame
    { 
      std::function<callback_func> f;
      boost::asio::ip::tcp::resolver resolver;
      const std::size_t iteration;

      frame(client_state& self, std::function<callback_func>&& f)
        : f(std::move(f)), resolver(self.strand.context()), iteration(self.iteration)
      {}
    };

    struct handler : boost::asio::coroutine
    {
      std::shared_ptr<client_state> self_;
      std::shared_ptr<frame> frame_;

      explicit handler(std::shared_ptr<client_state> self, std::shared_ptr<frame>&& in)
        : boost::asio::coroutine(), self_(std::move(self)), frame_(std::move(in))
      {}

      void operator()(boost::system::error_code error = {})
      {
        LWSF_VERIFY(self_ && frame_);

        client_state& self = *self_;
        assert(self.strand.running_in_this_thread());
        BOOST_ASIO_CORO_REENTER(*this)
        {
          struct resolve
          {
            handler continue_;

            void operator()(const boost::system::error_code error, const boost::asio::ip::tcp::resolver::results_type& ips)
            {
              if (error)
                std::move(continue_)(error);
              else if (ips.empty())
                std::move(continue_)(boost::asio::error::host_not_found);
              else if (continue_.self_)
              {
                continue_.self_->endpoint = *ips.begin();
                std::move(continue_)(error);
              }
            }
          };

          struct on_timeout
          {
            std::shared_ptr<client_state> self_;
            std::shared_ptr<frame> frame_;
            void operator()(boost::system::error_code error) const
            {
              LWSF_VERIFY(frame_ && self_);
              assert(self_->strand.running_in_this_thread());

              frame_->resolver.cancel();
              self_->close();
            }
          };

          set_timeout(self_, config::connect_timeout, on_timeout{self_, frame_});

          MDEBUG("Resolving " << self.host << " for HTTP");
          BOOST_ASIO_CORO_YIELD frame_->resolver.async_resolve(
            self.host, std::to_string(self.port), boost::asio::bind_executor(self.strand, resolve{*this})
          );

          if (!error)
          {
            MDEBUG("Connecting to " << self.endpoint << " / " << self.host << " for HTTP");
            BOOST_ASIO_CORO_YIELD self.sock.next_layer().async_connect(
              self.endpoint, boost::asio::bind_executor(self.strand, std::move(*this))
            );

            if (error)
              MERROR("Failed to connect to " << self.host << ": " << error.message());
          }
          else
            MERROR("Failed to resolve TCP/IP address for " << self.host << ": " << error.message());

          if (self_->iteration <= frame_->iteration)
            frame_->f(error);
        }
      }
    };

    LWSF_VERIFY(self);
    handler{self, std::make_shared<frame>(*self, std::move(f))}();
  }

  void client::socks::operator()(std::shared_ptr<client_state> self, std::function<callback_func> f) const
  {
    struct handler
    {
      std::shared_ptr<client_state> self_;
      std::function<callback_func> f_;

      void operator()(boost::system::error_code error, boost::asio::ip::tcp::socket&& sock)
      {
        LWSF_VERIFY(self_ && f_);

        if (error)
          MERROR("Failed socks connection: " << error.message());
        self_->sock.next_layer() = std::move(sock);

        std::function<callback_func> f{std::move(f_)};
        boost::asio::dispatch(self_->strand, [f = std::move(f), error] { f(error); });
      };
    };

    LWSF_VERIFY(self && f);

    std::shared_ptr<::net::socks::client> proxy = ::net::socks::make_connect_client(
      std::move(self->sock.next_layer()), ::net::socks::version::v4a, handler{self, f}
    );

    bool is_set = false;
    std::uint32_t ip_address = 0;
    if (epee::string_tools::get_ip_int32_from_string(ip_address, self->host))
      is_set = proxy->set_connect_command(epee::net_utils::ipv4_network_address{ip_address, self->port});
    else
      is_set = proxy->set_connect_command(self->host, self->port);
      
    if (is_set)
    {
      set_timeout(self, config::connect_timeout, ::net::socks::client::async_close{proxy});
      is_set = ::net::socks::client::connect_and_send(std::move(proxy), proxy_address);
    }

    if (!is_set)
    {
      MERROR("Failed to initiate socks proxy");
      f(boost::asio::error::fault);
    } 
  }

  void client::init(boost::asio::io_context& io, std::string host, std::string prefix, std::uint16_t port, epee::net_utils::ssl_options_t ssl)
  {
    const boost::lock_guard<boost::mutex> lock{sync_};
    state_ = std::make_shared<client_state>(io, std::move(host), std::move(prefix), port, std::move(ssl), proxy_);
  }
 
  client::~client()
  {}

  void client::shutdown()
  {
    const boost::lock_guard<boost::mutex> lock{sync_};
    state_ = nullptr;
  }

  bool client::is_connected() const noexcept
  {
    const boost::lock_guard<boost::mutex> lock{sync_};
    return state_ && state_->is_connected;
  }

  void client::set_proxy(std::function<connect_func> connector)
  {
    LWSF_VERIFY(connector);
    const boost::lock_guard<boost::mutex> lock{sync_};
    proxy_ = std::move(connector);
    if (state_)
      state_ = std::make_shared<client_state>(state_->strand.context(), state_->host, state_->prefix, state_->port, state_->ssl, proxy_);
  }

  void client::ws_async(std::string target, std::string protocol, std::function<ws_func> notifier)
  {
    std::shared_ptr<client_state> self;
    {
      const boost::lock_guard<boost::mutex> lock{sync_};
      self = state_;
      state_ = std::make_shared<client_state>(self->strand.context(), self->host, self->prefix, self->port, self->ssl, proxy_);
    }
    LWSF_VERIFY(self);

    struct start_ws
    {
      std::weak_ptr<client_state> self_;
      std::string target_;
      std::string protocol_;
      std::function<ws_func> notifier_;

      void operator()(const std::error_code error, epee::byte_slice)
      {
        const auto self = self_.lock();
        LWSF_VERIFY(self && notifier_);
        if (error)
          return notifier_(error, nullptr);

        std::string host;
        boost::system::error_code ec{};
        boost::asio::ip::make_address_v6(self->host, ec);
        const bool https = self->ssl_status == epee::net_utils::ssl_support_t::e_ssl_support_enabled;
        if (!ec)
          host = "[" + host + "]:" + std::to_string(self->port);
        else if ((https && self->port == 443) || (!https && self->port == 80))
          host = self->host;
        else
          host = self->host + ":" + std::to_string(self->port);

        if (self->ssl_status == epee::net_utils::ssl_support_t::e_ssl_support_enabled)
          websocket::async_start(std::move(self->sock), self->strand.context(), std::move(host), std::move(target_), std::move(protocol_), std::move(notifier_));
        else
          websocket::async_start(std::move(self->sock.next_layer()), self->strand.context(), std::move(host), std::move(target_), std::move(protocol_), std::move(notifier_));
      }
    };
 
    queue_async_(self, {}, {}, start_ws{self, std::move(target), std::move(protocol), std::move(notifier)}, boost::beast::http::verb::subscribe);
  }

  void client::post_async(std::string url, epee::byte_slice json_body, std::function<server_response_func> notifier) const
  {
    return queue_async(std::move(url), std::move(json_body), std::move(notifier), boost::beast::http::verb::post);
  }

  void client::get_async(std::string url, std::function<server_response_func> notifier) const
  {
    if (!notifier)
      throw std::logic_error{"net::http::client::get_async requires callback"};
    return queue_async(std::move(url), epee::byte_slice{}, std::move(notifier), boost::beast::http::verb::get);
  }
}}} // lwsf // internal // http

