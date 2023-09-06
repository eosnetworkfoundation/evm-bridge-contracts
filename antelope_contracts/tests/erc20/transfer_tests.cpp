
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

#include "erc20_tester.hpp"

using namespace eosio;
using namespace eosio::chain;
using namespace erc20_test;
using namespace eosio::testing;
using mvo = fc::mutable_variant_object;

using intx::operator""_u256;
constexpr size_t kAddressLength{20};

struct transfer_tester : erc20_tester {
    transfer_tester() {
        create_accounts({"alice"_n});
        transfer_token(eos_token_account, faucet_account_name, "alice"_n, make_asset(10000'0000));
        create_accounts({"bob"_n});
        transfer_token(eos_token_account, faucet_account_name, "bob"_n, make_asset(10000'0000));
        produce_block();
        // init();
    }

    void gen_bridgemessage(const char* dest, intx::uint256 value) {
        bytes calldata;

        auto dest_buffer = erc20_test::from_hex(dest);
        uint8_t value_buffer[32] = {};
        intx::be::store(value_buffer, value);

        calldata.reserve(kAddressLength + 32);
        calldata.insert(calldata.end(), dest_buffer->data(), dest_buffer->data() + kAddressLength);
        calldata.insert(calldata.end(), value_buffer, value_buffer + 32);

        // Cannot directly send message to erc20

        fc::variants arr;
        arr.push_back(fc::variant("bridge_message_v0"));
        arr.push_back(mvo()
            ("receiver", erc20_account.to_string())
            ("sender", "4ea3b729669bf6c34f7b80e5d6c17db71f89f21f") // contract addr at nonce 0
            ("timestamp","2020-01-01T00:00:00.000000")
            ("value", "0000000000000000000000000000000000000000000000000000000000000000")
            ("data", 
            "653332e5" //sha("bridgeTransferV0(address,uint256,string)")
            "000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbb3d0e000000000000" // bob- dest account
            "0000000000000000000000000000000000000000000000000000000000001388" // hex(5000)-ERC-20 val
            "0000000000000000000000000000000000000000000000000000000000000060" // hex(96)-memo offset
            "0000000000000000000000000000000000000000000000000000000000000004" // memo len
            "aabbccdd00000000000000000000000000000000000000000000000000000000" // memo data aligned to 32 bytes
            ));

        fc::variants arr_hacker_solidity_contract;
        arr_hacker_solidity_contract.push_back(fc::variant("bridge_message_v0"));
        arr_hacker_solidity_contract.push_back(mvo()
            ("receiver", erc20_account.to_string())
            ("sender", "aaaabbbbccccdddd111122223333444455556666") // hacker's solidity contract
            ("timestamp","2020-01-01T00:00:00.000000")
            ("value", "0000000000000000000000000000000000000000000000000000000000000000")
            ("data", 
            "653332e5" //sha("bridgeTransferV0(address,uint256,string)")
            "000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbb3d0e000000000000" // bob- dest account
            "0000000000000000000000000000000000000000000000000000000000001388" // hex(5000)-ERC-20 val
            "0000000000000000000000000000000000000000000000000000000000000060" // hex(96)-memo offset
            "0000000000000000000000000000000000000000000000000000000000000004" // memo len
            "aabbccdd00000000000000000000000000000000000000000000000000000000" // memo data aligned to 32 bytes
            ));

        // hacker can't trigger the bridge from other solidity contract
        BOOST_REQUIRE_EXCEPTION(
            push_action(
            evm_account, "sendbridgemsg"_n, evm_account, mvo()("message", arr_hacker_solidity_contract)),
            eosio_assert_message_exception, 
            eosio_assert_message_is("ERC-20 token not registerred"));

        // only evm_runtime can call onbridgemsg
        BOOST_REQUIRE_EXCEPTION(push_action(
            erc20_account, "onbridgemsg"_n, "alice"_n, mvo()("message", arr)),
            eosio_assert_message_exception, 
            eosio_assert_message_is("invalid sender of onbridgemsg"));

        // Go through stub
        push_action(
            evm_account, "sendbridgemsg"_n, evm_account, mvo()("message", arr));
    }
};

BOOST_AUTO_TEST_SUITE(erc20_tests)
BOOST_FIXTURE_TEST_CASE(eos_side_transfer, transfer_tester)
try {
    BOOST_REQUIRE(1 == 1);

    auto usdt_symbol = symbol::from_string("4,USDT");

    transfer_token(token_account, faucet_account_name, "alice"_n, make_asset(10000'0000, usdt_symbol));

    auto trace = transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, usdt_symbol), "0x0000000000000000000000000000000000000000");
    /*
        BOOST_TEST_MESSAGE(trace->action_traces.size());
        for (const auto& t:trace->action_traces) {
            BOOST_TEST_MESSAGE(std::string("receiver:")+ t.receiver.to_string());
            BOOST_TEST_MESSAGE(std::string("account:")+ t.act.account.to_string());
            BOOST_TEST_MESSAGE(std::string("name:")+ t.act.name.to_string());
        }
    */
    // TODO: call init of erc20
    // TODO: check call data
    BOOST_REQUIRE(trace->action_traces.back().receiver == evm_account);
    BOOST_REQUIRE(trace->action_traces.back().act.account == evm_account);
    BOOST_REQUIRE(trace->action_traces.back().act.name.to_string() == "call");

    BOOST_REQUIRE_EXCEPTION(transfer_token(eos_token_account, "alice"_n, erc20_account, make_asset(10000), "0x0000000000000000000000000000000000000000"),
                            eosio_assert_message_exception, eosio_assert_message_is("received unregistered token"));

    produce_block();
}
FC_LOG_AND_RETHROW()


BOOST_FIXTURE_TEST_CASE(withdraw_fee, transfer_tester)
try {
    BOOST_REQUIRE(1 == 1);

    auto usdt_symbol = symbol::from_string("4,USDT");

    transfer_token(token_account, faucet_account_name, "alice"_n, make_asset(10000'0000, usdt_symbol));

    BOOST_REQUIRE_EXCEPTION(push_action(
        erc20_account, "withdrawfee"_n, erc20_account, mvo()("token_contract", token_account)("to", "alice"_n)("quantity", make_asset(100, usdt_symbol))("memo", "hello1")),
        eosio_assert_message_exception, eosio_assert_message_is("overdrawn balance"));

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, usdt_symbol), "0x0000000000000000000000000000000000000000");

    BOOST_REQUIRE_EXCEPTION(push_action(
        erc20_account, "withdrawfee"_n, erc20_account, mvo()("token_contract", token_account)("to", "alice"_n)("quantity", make_asset(101, usdt_symbol))("memo", "hello2")),
        eosio_assert_message_exception, eosio_assert_message_is("overdrawn balance"));

    push_action(
        erc20_account, "withdrawfee"_n, erc20_account, mvo()("token_contract", token_account)("to", "alice"_n)("quantity", make_asset(50, usdt_symbol))("memo", "hello3"));

    push_action(
        erc20_account, "withdrawfee"_n, erc20_account, mvo()("token_contract", token_account)("to", "alice"_n)("quantity", make_asset(50, usdt_symbol))("memo", "hello4"));

    BOOST_REQUIRE_EXCEPTION(push_action(
        erc20_account, "withdrawfee"_n, erc20_account, mvo()("token_contract", token_account)("to", "alice"_n)("quantity", make_asset(50, usdt_symbol))("memo", "hello5")),
        eosio_assert_message_exception, eosio_assert_message_is("overdrawn balance"));

    produce_block();
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(set_ingress_fee, transfer_tester)
try {
    BOOST_REQUIRE(1 == 1);

    auto usdt_symbol = symbol::from_string("4,USDT");

    transfer_token(token_account, faucet_account_name, "alice"_n, make_asset(10000'0000, usdt_symbol));

    push_action(
        erc20_account, "setingressfee"_n, erc20_account, mvo()("token_contract", token_account)("ingress_fee", make_asset(200, usdt_symbol)));

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, usdt_symbol), "0x0000000000000000000000000000000000000000");

    BOOST_REQUIRE_EXCEPTION(push_action(
        erc20_account, "withdrawfee"_n, erc20_account, mvo()("token_contract", token_account)("to", "alice"_n)("quantity", make_asset(201, usdt_symbol))("memo", "hello6")),
        eosio_assert_message_exception, eosio_assert_message_is("overdrawn balance"));

    push_action(
        erc20_account, "withdrawfee"_n, erc20_account, mvo()("token_contract", token_account)("to", "alice"_n)("quantity", make_asset(200, usdt_symbol))("memo", "hello7"));

    produce_block();
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(evm_side_transfer, transfer_tester)
try {
    BOOST_REQUIRE(1 == 1);

    auto usdt_symbol = symbol::from_string("4,USDT");

    transfer_token(token_account, faucet_account_name, "alice"_n, make_asset(10000'0000, usdt_symbol));

    // Give erc20 some fund
    // 1 EOS = 10000
    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, usdt_symbol), "0x0000000000000000000000000000000000000000");
    BOOST_REQUIRE(10000 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount());
    produce_block();
    // reserved addr for bob
    // TODO: include silkworm and call function to generate it.
    const char bob[] = "0xbbbbbbbbbbbbbbbbbbbbbbbb3d0e000000000000";

    // EVM has precision of 6
    // 5000 /1000000 = 0.005 USDT = 50
    gen_bridgemessage(bob, 5000);

    BOOST_REQUIRE(10000 - 50 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount());

    BOOST_REQUIRE(50 == get_balance("bob"_n, token_account, symbol::from_string("4,USDT")).get_amount());
}
FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
