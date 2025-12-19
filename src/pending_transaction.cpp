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

#include "pending_transaction.h"

#include <boost/filesystem/operations.hpp>
#include <fstream>
#include <stdexcept>
#include "backend.h"
#include "byte_slice.h"   // monero/contrib/epee/include
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "error.h"
#include "numeric.h"
#include "string_tools.h" // monero/contrib/epee/include
#include "utils/encrypted_file.h"
#include "wire.h"
#include "wire/msgpack.h"
#include "wire/wrapper/trusted_array.h"

namespace lwsf { namespace internal
{
  namespace backend
  {
    static void read_bytes(wire::reader& src, std::shared_ptr<transaction>& dest)
    {
      if (!dest)
        dest = std::make_shared<backend::transaction>();
      read_bytes(src, *dest);
    }

    static void write_bytes(wire::writer& dest, const std::shared_ptr<transaction>& src)
    {
      if (!src)
        throw std::logic_error{"Unexpected nullptr in write_bytes"};
      write_bytes(dest, *src);
    }
  }

  namespace
  {
    constexpr std::string_view tx_file_magic{"lwsf-tx-1.0"};

    struct txes_file
    {
      std::vector<std::shared_ptr<backend::transaction>> txes;
    };

    void read_bytes(wire::reader& src, std::shared_ptr<backend::transaction>& dest)
    {
      if (!dest)
        dest = std::make_shared<backend::transaction>();
      read_bytes(src, *dest);
    }
    void write_bytes(wire::writer& dest, const std::shared_ptr<backend::transaction> src)
    {
      if (!src)
        WIRE_DLOG_THROW_(error::unexpected_nullptr);
      write_bytes(dest, *src);
    }

    template<typename F, typename T>
    void txes_map(F& format, T& self)
    {
      wire::object(format, wire::field("txes", wire::trusted_array(std::ref(self.txes))));
    }
    WIRE_DEFINE_OBJECT(txes_file, txes_map);

    cryptonote::transaction get_tx(expect<cryptonote::transaction>&& source)
    {
      if (source)
        return {std::move(*source)};
      return {};
    }
  }


  pending_transaction::pending_transaction(std::shared_ptr<backend::wallet> wallet, std::string error, std::vector<std::shared_ptr<backend::transaction>> local)
    : wallet_(std::move(wallet)), local_(std::move(local)), error_(std::move(error))
  {
    if (!wallet_)
      throw std::invalid_argument{"lwsf::internal::pending_transaction cannot be given nullptr backend"};

    for (const auto& e : local_)
    {
      if (!e)
        throw std::invalid_argument{"lwsf::internal::pending_transaction cannot be given nullptr backend::transaction"};
    }
  }

  std::unique_ptr<pending_transaction> pending_transaction::load_from_file(std::shared_ptr<backend::wallet> wallet, const std::string& filename)
  {
    if (!wallet)
      throw std::invalid_argument{"lwsf::internal::pending_transaction::load_from_file cannot be given nullptr backend"};

    epee::byte_slice file = try_load(filename, tx_file_magic);
    if (file.empty())
      return std::make_unique<pending_transaction>(wallet, "Invalid path/file for tx");

    expect<epee::byte_slice> payload = epee::byte_slice{};
    {
      const boost::lock_guard<boost::mutex> lock{wallet->sync};
      payload = decrypt(std::move(file), epee::as_byte_span(unwrap(unwrap(wallet->primary.view.sec))));
    }
    if (!payload)
      return std::make_unique<pending_transaction>(wallet, payload.error().message());

    txes_file dest{};
    if (std::error_code error = wire::msgpack::from_bytes(std::move(*payload), dest))
      return std::make_unique<pending_transaction>(wallet, error.message());
    return std::make_unique<pending_transaction>(wallet, "", std::move(dest.txes));
  }

  pending_transaction::~pending_transaction()
  {}

  bool pending_transaction::send()
  {
    if (!error_.empty())
      return false;

    for (auto e : local_)
    {
      const std::error_code error = wallet_->send_tx(e->raw_bytes.clone());
      if (error)
      {
        error_ = error.message();
        return false;
      }
      const boost::lock_guard<boost::mutex> lock{wallet_->sync};
      auto entry = wallet_->primary.txes.try_emplace(e->id).first;
      if (!entry->second)
        entry->second = std::move(e);
    }
    return true;
  }

  int pending_transaction::status() const
  {
    return error_.empty() ? Status_Ok : Status_Error;
  }

  bool pending_transaction::commit(const std::string &filename, const bool overwrite)
  {
    assert(wallet_); // see constructor
    if (!error_.empty())
      return false;
    if (filename.empty())
      return send();

    if (boost::filesystem::exists(filename) && !overwrite)
    {
      error_ = "File already exists";
      return false;
    }

    expect<epee::byte_slice> bytes = epee::byte_slice{};
    {
      epee::byte_stream sink{};
      const txes_file source{local_};
      if (std::error_code error = wire::msgpack::to_bytes(sink, source))
      {
        error_ = error.message();
        return false;
      }

      const boost::lock_guard<boost::mutex> lock{wallet_->sync};
      bytes = encrypt(
        tx_file_magic,
        epee::byte_slice{std::move(sink)},
        0 /* iterations */,
        epee::as_byte_span(unwrap(unwrap(wallet_->primary.view.sec)))
      );
    }

    if (!bytes)
    {
      error_ = bytes.error().message();
      return false;
    }

    std::ofstream out{filename};
    out.write(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    return out.good();
  }

  std::uint64_t pending_transaction::amount() const
  {
    safe_uint64_t out{};
    for (const auto& e : local_)
      out += e->amount;
    return out;
  }

  std::uint64_t pending_transaction::fee() const
  {
    safe_uint64_t out{};
    for (const auto& e : local_)
      out += e->fee;
    return out;
  }

  std::vector<std::string> pending_transaction::txid() const
  {
    std::vector<std::string> out;
    for (const auto& e : local_)
      out.push_back(epee::to_hex::string(epee::as_byte_span(e->id)));
    return out;
  }
}} // lwsf // internal
