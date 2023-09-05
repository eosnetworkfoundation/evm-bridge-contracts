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
constexpr eosio::name erc2o_account(eosio::name("eosio.erc2o"));

constexpr unsigned evm_precision = 18; // precision of native token(aka.EOS) in EVM side
constexpr eosio::symbol native_token_symbol("EOS", 4u);
constexpr intx::uint256 minimum_natively_representable = intx::exp(10_u256, intx::uint256(evm_precision - native_token_symbol.precision()));


}  // namespace erc20