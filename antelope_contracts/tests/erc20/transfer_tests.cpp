
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
        BOOST_REQUIRE_EXCEPTION(push_action(
                                    erc20_account, "onbridgemsg"_n, "alice"_n, mvo()("receiver", erc20_account)("sender", bytes())("timestamp", eosio::chain::time_point())("value", bytes())("data", calldata)),
                                missing_auth_exception, eosio::testing::fc_exception_message_starts_with("missing authority"));

        // Go through stub
        push_action(
            evm_account, "sendbridgemsg"_n, "alice"_n, mvo()("receiver", erc20_account)("sender", bytes())("timestamp", eosio::chain::time_point())("value", bytes())("data", calldata));
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
                            eosio_assert_message_exception, eosio_assert_message_is("received unexpected token"));

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
    // 5000 /1000000 = 0.005 EOS = 50
    gen_bridgemessage(bob, 5000);

    BOOST_REQUIRE(10000 - 50 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount());

    BOOST_REQUIRE(50 == get_balance("bob"_n, token_account, symbol::from_string("4,USDT")).get_amount());
}
FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()