#pragma once

#include <eosio/eosio.hpp>
#include <intx/intx.hpp>

using namespace eosio;
using namespace intx;

namespace evmutil {

typedef std::vector<char> bytes;

constexpr size_t kAddressLength{20};
constexpr size_t kHashLength{32};
constexpr uint64_t default_evm_gaslimit = 500000;
constexpr uint64_t default_evm_init_gaslimit = 10000000;

constexpr eosio::name default_evm_account(eosio::name("evm.xsat"));
constexpr eosio::name default_endrmng_account(eosio::name("endrmng.xsat"));
constexpr eosio::name default_poolreg_account(eosio::name("poolreg.xsat"));

constexpr unsigned evm_precision = 18; // precision of native token(aka.EOS) in EVM side
constexpr eosio::symbol default_native_token_symbol("BTC", 8u);

}  // namespace evmutil