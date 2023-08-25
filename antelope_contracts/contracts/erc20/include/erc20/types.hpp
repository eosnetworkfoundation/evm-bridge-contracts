#pragma once

#include <eosio/eosio.hpp>
#include <intx/intx.hpp>

using namespace eosio;
using namespace intx;

namespace erc20 {

typedef std::vector<char> bytes;

constexpr size_t kAddressLength{20};
constexpr size_t kHashLength{32};
constexpr unsigned evm_precision = 6;
constexpr uint64_t evm_gaslimit = 500000;
constexpr uint64_t evm_init_gaslimit = 50000000;
//constexpr eosio::name token_account(eosio::name("tethertether"));
constexpr eosio::symbol token_symbol("USDT", 4u);
constexpr eosio::name evm_account(eosio::name("eosio.evm"));
constexpr intx::uint256 minimum_natively_representable = intx::exp(10_u256, intx::uint256(evm_precision - token_symbol.precision()));
static_assert(evm_precision - token_symbol.precision() <= 14, "dust math may overflow a uint64_t");

}  // namespace erc20