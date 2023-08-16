
#include <cstdint>
#include <cstring>
#include <fc/crypto/hex.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/variant_object.hpp>
#include <intx/intx.hpp>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/fixed_bytes.hpp>
#include <eosio/testing/tester.hpp>
#include <optional>
#include <contracts.hpp>
#include "erc2o_tester.hpp"

using namespace eosio;
using namespace eosio::chain;
using mvo = fc::mutable_variant_object;

using intx::operator""_u256;

struct transfer_tester : erc2o_tester {
    transfer_tester() {
        create_accounts({"alice"_n});
        transfer_token(eos_token_account, faucet_account_name, "alice"_n, make_asset(10000'0000));
        create_accounts({"bob"_n});
        transfer_token(eos_token_account, faucet_account_name, "bob"_n, make_asset(10000'0000));
        produce_block();
        //init();
    }
};

BOOST_AUTO_TEST_SUITE(erc2o_tests)
BOOST_FIXTURE_TEST_CASE(hello_world, transfer_tester) try {
    BOOST_REQUIRE(1 == 1);
}
FC_LOG_AND_RETHROW()
BOOST_AUTO_TEST_SUITE_END()
