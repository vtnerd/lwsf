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

#include "encrypted_file.h"

#include <fstream>
#include <sodium/core.h>
#include <sodium/crypto_pwhash_argon2id.h>
#include <sodium/randombytes.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <stdexcept>

#include "byte_stream.h" // monero/contrib/epee/include
#include "error.h"
#include "lwsf_config.h"
#include "wire.h"
#include "wire/msgpack.h"

namespace lwsf { namespace internal
{
  namespace
  {
    struct encrypted_file
    {
      std::string cipher;        //!< Name of cipher+authentication used
      std::string pwhasher;      //!< Name of pwhasher used
      epee::byte_slice salt;     //!< Pwhashing salt
      epee::byte_slice nonce;    //!< Encryption iv/nonce
      epee::byte_slice epayload; //!< Encrypted contents
      std::uint64_t iterations;  //!< Pwhashing iterations
      std::uint32_t memory;      //!< Pwhashing memory

      encrypted_file() = delete;

      static epee::byte_slice get_random(const std::size_t length)
      {
        if (sodium_init() < 0)
          throw std::runtime_error{"Failed to initialize libsodium"};

        epee::byte_stream out;
        out.put_n(0, length);
        randombytes_buf(out.data(), length);
        return epee::byte_slice{std::move(out)};
      }

      static constexpr const char* pwhasher_name() noexcept
      {
        return "argon2id";
      }
      static constexpr int pwhash_algorithm() noexcept
      {
        return crypto_pwhash_argon2id_ALG_ARGON2ID13;
      }
      static constexpr std::size_t salt_size() noexcept
      {
        return crypto_pwhash_argon2id_SALTBYTES;
      }
      static constexpr std::uint64_t ops_min() noexcept { return 5; }
      static constexpr std::size_t memory_limit() noexcept { return 7 * 1024 * 1024; }
      static epee::byte_slice get_salt() { return get_random(salt_size()); }

      static constexpr const char* cipher_name() noexcept
      {
        return "chacha20-poly1305_ietf";
      }
      static constexpr unsigned long long max_size() noexcept
      {
        return crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX;
      }
      static constexpr std::size_t key_size() noexcept
      {
        return crypto_aead_chacha20poly1305_ietf_KEYBYTES;
      }
      static constexpr std::size_t tag_size() noexcept
      {
        return crypto_aead_chacha20poly1305_ietf_ABYTES;
      }
      static constexpr std::size_t nonce_size() noexcept
      {
        return crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
      }
      static epee::byte_slice get_nonce() { return get_random(nonce_size()); }

      std::array<std::uint8_t, 32> get_key(const epee::span<const std::uint8_t> password) const
      {
        if (sodium_init() < 0)
          throw std::runtime_error{"Failed to initialize libsodium"};

        std::array<std::uint8_t, key_size()> key{{}};
        if (crypto_pwhash_argon2id(
          key.data(), key.size(),
          reinterpret_cast<const char*>(password.data()), password.size(),
          salt.data(),
          iterations, memory, pwhash_algorithm()) != 0)
        {
          throw std::runtime_error{std::string{pwhasher_name()} + " failed"};
        }
        return key;
      }

      static encrypted_file make(const epee::byte_slice& upayload, const std::uint64_t iterations, const epee::span<const std::uint8_t> password)
      {
        if (sodium_init() < 0)
          throw std::runtime_error{"Failed to initialize libsodium"};

        if (max_size() < upayload.size())
          throw std::runtime_error{std::string{"Exceeded max size for "} + cipher_name()};
        if (std::numeric_limits<std::size_t>::max() - upayload.size() < tag_size())
          throw std::runtime_error{"Exceeded max size_t after authentication tag"};

        encrypted_file out{
          cipher_name(),
          pwhasher_name(),
          get_salt(),
          get_nonce(),
          nullptr,
          std::max(iterations, ops_min()),
          memory_limit()
        };

        const auto key = out.get_key(password);

        epee::byte_stream buffer;
        buffer.put_n(0, upayload.size() + tag_size());

        unsigned long long out_bytes = buffer.size();
        if (crypto_aead_chacha20poly1305_ietf_encrypt(
          buffer.data(), std::addressof(out_bytes),
          upayload.data(), upayload.size(),
          nullptr, 0,
          nullptr,
          out.nonce.data(), key.data()) != 0)
        {
          // this should basically never happen, so throw
          throw std::runtime_error{std::string{cipher_name()} + " encryption failed"};
        }

        out.epayload = epee::byte_slice{std::move(buffer)}.take_slice(out_bytes);
        return out;
      }

      //! \return Unencrypted payload, or `nullptr`.
      epee::byte_slice get_payload(const epee::span<const std::uint8_t> password) const
      {
        if (nonce.size() != nonce_size())
          return nullptr;
        if (salt.size() != salt_size())
          return nullptr;
        if (cipher != cipher_name())
          return nullptr;
        if (pwhasher != pwhasher_name())
          return nullptr;
        if (max_size() < epayload.size())
          return nullptr;

        if (sodium_init() < 0)
          throw std::runtime_error{"Failed to initialize libsodium"};

        const auto key = get_key(password);
        static_assert(key_size() == key.size());

        epee::byte_stream buffer;
        buffer.put_n(0, epayload.size());

        static_assert(
          std::numeric_limits<std::size_t>::max() <= std::numeric_limits<unsigned long long>::max()
        );

        unsigned long long out_bytes = buffer.size();
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
          buffer.data(), std::addressof(out_bytes),
          nullptr,
          epayload.data(), epayload.size(),
          nullptr, 0,
          nonce.data(), key.data()) != 0)
        {
          return nullptr;
        }

        return epee::byte_slice{std::move(buffer)}.take_slice(out_bytes);
      }
    };

    template<typename F, typename T>
    void map_encrypted_file(F& format, T& self)
    {
      wire::object(format,
        WIRE_FIELD(cipher),
        WIRE_FIELD(pwhasher),
        WIRE_FIELD(salt),
        WIRE_FIELD(nonce),
        WIRE_FIELD(epayload),
        WIRE_FIELD(iterations),
        WIRE_FIELD(memory)
      );
    }

    WIRE_DEFINE_OBJECT(encrypted_file, map_encrypted_file);
  }

  epee::byte_slice try_load(const std::string& filename, const std::string_view file_magic)
  {
    std::ifstream file{filename, std::ios::binary};
    if (!file.is_open())
      return nullptr;

    {
      std::string magic;
      magic.resize(file_magic.size());
      file.read(magic.data(), magic.size());
      if (!file.good() || magic != file_magic)
        return nullptr;
    }

    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    if (size < 0 || std::size_t(size) < file_magic.size())
      return nullptr;

    if (config::max_file_read_size < std::size_t(size))
      return nullptr;

    epee::byte_stream buffer;
    buffer.put_n(0, std::size_t(size) - file_magic.size());

    file.seekg(file_magic.size());
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

    if (file.good())
      return epee::byte_slice{std::move(buffer)};
    return nullptr;
  }

  expect<epee::byte_slice> encrypt(const std::string_view file_magic, epee::byte_slice payload, const std::uint64_t iterations, const epee::span<const std::uint8_t> password)
  {
    const auto contents = encrypted_file::make(payload, iterations, password);
    const std::size_t payload_size = payload.size();
    payload = nullptr; // free up some memory that is no longer needed

    epee::byte_stream buffer;
    buffer.reserve(payload_size + file_magic.size() + 2048);
    buffer.write(file_magic.data(), file_magic.size());

    if (std::error_code error = wire::msgpack::to_bytes(buffer, contents))
      return error;
    return epee::byte_slice{std::move(buffer)};
  }

  expect<epee::byte_slice> decrypt(epee::byte_slice encrypted, const epee::span<const std::uint8_t> password)
  {
    encrypted_file contents{};
    if (std::error_code error = wire::msgpack::from_bytes(std::move(encrypted), contents))
      return error;
    auto payload = contents.get_payload(epee::to_span(password));
    if (payload.empty())
      return {error::decryption};
    return payload;
  }
 
}} // lwsf // internal

