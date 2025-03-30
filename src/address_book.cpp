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

#include "address_book.h"

#include <boost/thread/lock_guard.hpp>
#include <utility>
#include "backend.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

namespace lwsf { namespace internal {

  namespace
  {
    void clear_addresses(std::vector<Monero::AddressBookRow*>& rows) noexcept
    {
      for (const auto row : rows)
        delete row;
      rows.clear();
    }

    struct force_refresh_
    {
      void operator()(address_book* ptr) const noexcept
      {
        try
        {
          ptr->refresh();
        }
        catch (...)
        {}
      }
    };

    using force_refresh = std::unique_ptr<address_book, force_refresh_>;
  }

  void address_book::clear_status()
  {
    error_string_.clear();
    error_ = Status_Ok;
  }

  address_book::address_book(std::shared_ptr<backend::wallet> data)
    : data_(std::move(data)), addresses_(), error_string_(), error_(Status_Ok)
  {}

  address_book::~address_book()
  {
    clear_addresses(addresses_);
  }

  bool address_book::addRow(const std::string &dst_addr , const std::string &payment_id, const std::string &description)
  {
    clear_status();

    cryptonote::address_parse_info info;
    if(!cryptonote::get_account_address_from_str(info, data_->get_net_type(), dst_addr))
    {
      error_string_ = "Invalid destination address";
      error_ = Invalid_Address;
      return false;
    }

    if (!payment_id.empty() && payment_id.size() != sizeof(crypto::hash8) * 2 && payment_id.size() != sizeof(crypto::hash) * 2)
    {
      error_string_ = "Invalid payment id";
      error_ = Invalid_Payment_Id;
      return false;
    }

    force_refresh force{this};
    auto row = std::make_unique<Monero::AddressBookRow>(addresses_.size(), dst_addr, payment_id, description);
    addresses_.push_back(row.get());
    row.release();

    const boost::lock_guard<boost::mutex> lock{data_->sync};
    data_->primary.addressbook.push_back(
      backend::address_book_entry{dst_addr, payment_id, description}
    );

    force.release();
    return true;
  }
  
  bool address_book::deleteRow(std::size_t rowId)
  {
    if (addresses_.size() <= rowId)
      return false;

    clear_status();
    force_refresh force{this};

    const std::unique_ptr<Monero::AddressBookRow> destroy{addresses_[rowId]};
    addresses_[rowId] = nullptr;
    addresses_.erase(addresses_.begin() + rowId);
    
    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (data_->primary.addressbook.size() <= rowId)
      return false;

    data_->primary.addressbook.erase(data_->primary.addressbook.begin() + rowId);
    force.release();
    return true;
  }

  bool address_book::setDescription(std::size_t index, const std::string &description)
  {
    clear_status();
    if (addresses_.size() <= index)
      return false;

    force_refresh force{this};
    
    const std::unique_ptr<Monero::AddressBookRow> destroy{addresses_[index]};
    addresses_[index] = nullptr; 
    addresses_[index] = new Monero::AddressBookRow{
      index, destroy->getAddress(), destroy->getPaymentId(), description
    };

    const boost::lock_guard<boost::mutex> lock{data_->sync};
    if (data_->primary.addressbook.size() <= index)
      return false;

    data_->primary.addressbook[index].description = description;
    force.release();
    return true;
  }

  void address_book::refresh()
  {
    try
    {
      clear_addresses(addresses_);

      const boost::lock_guard<boost::mutex> lock{data_->sync};
      addresses_.resize(data_->primary.addressbook.size());

      for (std::size_t i = 0; i < addresses_.size(); ++i)
      {
        const auto& current = data_->primary.addressbook[i];
        addresses_[i] = new Monero::AddressBookRow{
          i, current.address, current.payment_id, current.description
        };
      }
    }
    catch (...)
    {
      clear_addresses(addresses_);
    }
  }

  int address_book::lookupPaymentID(const std::string &payment_id) const
  {
    static constexpr const auto int_max = std::numeric_limits<int>::max();
    static_assert(int_max <= std::numeric_limits<std::size_t>::max());
    const std::size_t end = std::min(std::size_t(int_max), addresses_.size());

    // from primary implementation
    std::string long_payment_id = payment_id;
    long_payment_id.resize(64, '0');

    for (std::size_t i = 0; i < end; ++i)
    {
      std::string current = addresses_[i]->getPaymentId();
      if (payment_id == current)
        return i;
      if (long_payment_id == current)
        return i;
      // also from primary implementation
      current.resize(64, '0');
      if (payment_id == current)
        return i;
    }

    return -1;
  }
}} // lwsf // internal
