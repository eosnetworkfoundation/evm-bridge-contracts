#include "erc2o_tester.hpp"

#include <contracts.hpp>
#include <cstdint>
#include <cstring>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/fixed_bytes.hpp>
#include <eosio/testing/tester.hpp>
#include <fc/crypto/hex.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/variant_object.hpp>
#include <intx/intx.hpp>
#include <optional>

using namespace eosio;
using namespace eosio::chain;
using mvo = fc::mutable_variant_object;

using intx::operator""_u256;
namespace erc2o_test {
const eosio::chain::name eos_token_account("eosio.token");
const eosio::chain::symbol eos_token_symbol(4u, "EOS");
const eosio::chain::name token_account("tethertether");
const eosio::chain::symbol token_symbol(4u, "USDT");
const eosio::chain::name evm_account("eosio.evm");
const eosio::chain::name faucet_account_name("eosio.faucet");
const eosio::chain::name erc2o_account("eosio.erc2o");

erc2o_tester::erc2o_tester(std::string native_symbol_str) : native_symbol(symbol::from_string(native_symbol_str)) {
    create_accounts({eos_token_account, evm_account, token_account, faucet_account_name, erc2o_account});
    produce_block();

    set_code(eos_token_account, testing::contracts::eosio_token_wasm());
    set_abi(eos_token_account, testing::contracts::eosio_token_abi().data());

    push_action(eos_token_account,
                "create"_n,
                eos_token_account,
                mvo()("issuer", eos_token_account)("maximum_supply", asset(10'000'000'000'0000, native_symbol)));
    push_action(eos_token_account,
                "issue"_n,
                eos_token_account,
                mvo()("to", faucet_account_name)("quantity", asset(1'000'000'000'0000, native_symbol))("memo", ""));
    produce_block();

    set_code(token_account, testing::contracts::eosio_token_wasm());
    set_abi(token_account, testing::contracts::eosio_token_abi().data());

    push_action(token_account,
                "create"_n,
                token_account,
                mvo()("issuer", token_account)("maximum_supply", asset(10'000'000'000'0000, symbol::from_string("4,USDT"))));
    push_action(token_account,
                "issue"_n,
                token_account,
                mvo()("to", faucet_account_name)("quantity", asset(1'000'000'000'0000, symbol::from_string("4,USDT")))("memo", ""));

    produce_block();

    set_code(erc2o_account, testing::contracts::erc2o_wasm());
    set_abi(erc2o_account, testing::contracts::erc2o_abi().data());

    produce_block();

    set_code(evm_account, testing::contracts::evm_stub_wasm());
    set_abi(evm_account, testing::contracts::evm_stub_abi().data());

    produce_block();
    auto abi = fc::json::from_string(testing::contracts::eosio_token_abi().data()).template as<abi_def>();
    token_abi_ser.set_abi(std::move(abi), abi_serializer::create_yield_function(abi_serializer_max_time));
}

eosio::chain::transaction_trace_ptr erc2o_tester::transfer_token(eosio::chain::name token_account_name, eosio::chain::name from, eosio::chain::name to, eosio::chain::asset quantity, std::string memo) {
    return push_action(
        token_account_name, "transfer"_n, from, mvo()("from", from)("to", to)("quantity", quantity)("memo", memo));
}

}  // namespace erc2o_test