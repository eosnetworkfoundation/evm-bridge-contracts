#include "erc20_tester.hpp"

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
namespace erc20_test {
const eosio::chain::name eos_token_account("eosio.token");
const eosio::chain::symbol eos_token_symbol(4u, "EOS");
const eosio::chain::name token_account("tethertether");
const eosio::chain::symbol token_symbol(4u, "USDT");
const eosio::chain::name evm_account("eosio.evm");
const eosio::chain::name faucet_account_name("eosio.faucet");
const eosio::chain::name erc20_account("eosio.erc2o");

erc20_tester::erc20_tester(std::string native_symbol_str) : native_symbol(symbol::from_string(native_symbol_str)) {
    create_accounts({eos_token_account, evm_account, token_account, faucet_account_name, erc20_account});
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

    set_code(erc20_account, testing::contracts::erc20_wasm());
    set_abi(erc20_account, testing::contracts::erc20_abi().data());

    produce_block();

    // ./cleos push action eosio.erc2o init '[0]' -p eosio.erc2o
    push_action(erc20_account, "init"_n, erc20_account, mvo()("nonce", 0));

    produce_block();

    // ./cleos push action eosio.erc2o regtoken '[1,"usdt","EVM USDT Token","WUSDT","0.1000 USDT","0.0100 USDT","4ea3b729669bf6c34f7b80e5d6c17db71f89f21f",6]' -p eosio.erc2o
    push_action(erc20_account, "regtoken"_n, erc20_account, mvo()("nonce", 1)("eos_contract_name",token_account.to_string())("evm_token_name","EVM USDT V1")("evm_token_symbol","WUSDT")("min_deposit","0.1000 USDT")("deposit_fee","0.0100 USDT")("erc20_impl_address","4ea3b729669bf6c34f7b80e5d6c17db71f89f21f")("erc20_precision",6));

    produce_block();

    set_code(evm_account, testing::contracts::evm_stub_wasm());
    set_abi(evm_account, testing::contracts::evm_stub_abi().data());

    produce_block();
    auto abi = fc::json::from_string(testing::contracts::eosio_token_abi().data()).template as<abi_def>();
    token_abi_ser.set_abi(std::move(abi), abi_serializer::create_yield_function(abi_serializer_max_time));
}

eosio::chain::transaction_trace_ptr erc20_tester::transfer_token(eosio::chain::name token_account_name, eosio::chain::name from, eosio::chain::name to, eosio::chain::asset quantity, std::string memo) {
    return push_action(
        token_account_name, "transfer"_n, from, mvo()("from", from)("to", to)("quantity", quantity)("memo", memo));
}

}  // namespace erc20_test