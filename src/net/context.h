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

#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/thread/mutex.hpp>
#include <chrono>
#include <future>
#include <memory>
#include <utility>

namespace lwsf { namespace internal { namespace net
{
  template<typename T>
  struct to_future
  {
    struct inner
    {
      std::promise<T> promise;
      inner()
        : promise()
      {}
    };

    std::shared_ptr<inner> inner_;

    to_future()
      : inner_(std::make_shared<inner>())
    {}

    void operator()(T value)
    { 
      LWSF_VERIFY(inner_);
      inner_->promise.set_value(std::move(value));
    }
  };

  struct context
  {
    std::weak_ptr<int> restart_;
    boost::asio::io_context io_;
    boost::mutex sync_;

    explicit context();

    //! Restart `io_` if needed, and get an object that prevents future restarts.
    std::shared_ptr<int> restart_asio();

    template<typename T, typename F>
    T wait_for(F f)
    {
      to_future<T> callable{};
      auto value = callable.inner_->promise.get_future();
      f(std::move(callable));
      for (;;)
      {
        switch (value.wait_for(std::chrono::seconds{0}))
        {
        case std::future_status::deferred:
        case std::future_status::ready:
          return value.get();

        case std::future_status::timeout:
          {
            const auto restart_lock = restart_asio();
            io_.run_one_for(std::chrono::milliseconds{100});
          }
          break;
        };
      }
      throw std::logic_error{"unreachable"};
    }
  };

}}} // lwsf // internal // net
