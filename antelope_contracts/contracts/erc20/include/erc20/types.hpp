#pragma once

#include <eosio/eosio.hpp>
#include <intx/intx.hpp>

using namespace eosio;
using namespace intx;

namespace erc20 {

typedef std::vector<char> bytes;

constexpr size_t kAddressLength{20};
constexpr size_t kHashLength{32};
constexpr uint64_t evm_gaslimit = 500000;
constexpr uint64_t evm_init_gaslimit = 10000000;
constexpr eosio::name evm_account(eosio::name("eosio.evm"));

}  // namespace erc20