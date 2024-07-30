
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
#include <string>
#include <vector>

#include "erc20_tester.hpp"
#include <erc20/bytecode.hpp>

using namespace eosio;
using namespace eosio::chain;
using namespace erc20_test;
using namespace eosio::testing;
using mvo = fc::mutable_variant_object;

using intx::operator""_u256;
constexpr size_t kAddressLength{20};

struct it_tester : erc20_tester {
    std::string address_str32(const evmc::address& x) {
        std::stringstream hex_ss;
        for (uint8_t c : x.bytes) {
            hex_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        int hex_length = hex_ss.str().length();

        std::stringstream ss;
        ss << std::setfill('0') << std::setw(64 - hex_length) << 0;
        for (uint8_t c : x.bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        return ss.str();
    }

    std::string uint256_str32(intx::uint256 x) {
        uint8_t buffer[32] = {};
        intx::be::store(buffer, x);

        std::stringstream ss;

        for (uint8_t c : buffer) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        return ss.str();
    }

    std::string int_str32(uint32_t x) {
        std::stringstream hex_ss;
        hex_ss << std::hex << x;
        int hex_length = hex_ss.str().length();

        std::stringstream ss;
        ss << std::setfill('0') << std::setw(64 - hex_length) << 0 << std::hex << std::uppercase << x;
        return ss.str();
    }

    std::string str_to_hex(const std::string& str) {
        std::stringstream ss;
        for (char c : str) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        return ss.str();
    }

    std::string data_str32(const std::string& str) {
        std::stringstream ss;
        ss << str;
        int ps = 64 - (str.length() % 64);
        if (ps == 64) {
            ps = 0;
        }
        ss << std::setw(ps) << std::setfill('0') << "";
        return ss.str();
    }

    std::string evm_address;
    it_tester() : erc20_tester(true) {
        create_accounts({"alice"_n});
        transfer_token(eos_token_account, faucet_account_name, "alice"_n, make_asset(10000'0000));
        produce_block();
        transfer_token(token_account, faucet_account_name, "alice"_n, make_asset(10000'0000, token_symbol));
        produce_block();
        create_accounts({"bob"_n});
        transfer_token(eos_token_account, faucet_account_name, "bob"_n, make_asset(10000'0000));
        produce_block();
        transfer_token(token_account, faucet_account_name, "bob"_n, make_asset(10000'0000, token_symbol));

        produce_block();

        evm_address = getSolidityContractAddress();
        BOOST_REQUIRE_MESSAGE(evm_address.size() == 42, std::string("address wrong: ") + evm_address);

        // init();
    }

    std::string getSolidityContractAddress() {
        auto r = getRegistedTokenInfo();
        return vec_to_hex(r.address, true);
    }

    token_t getRegistedTokenInfo() {
        auto& db = const_cast<chainbase::database&>(control->db());

        const auto* existing_tid = db.find<table_id_object, by_code_scope_table>(
            boost::make_tuple(erc20_account, erc20_account, "tokens"_n));
        if (!existing_tid) {
            return {};
        }
        const auto* kv_obj = db.find<chain::key_value_object, chain::by_scope_primary>(
            boost::make_tuple(existing_tid->id, 0));

        auto r = fc::raw::unpack<token_t>(
            kv_obj->value.data(),
            kv_obj->value.size());
        return r;
    }

    intx::uint256 egressFee(std::optional<exec_callback> callback = {}, std::optional<bytes> context = {}) {
        exec_input input;
        input.context = context;
        input.to = *erc20_test::from_hex(evm_address.c_str());
        BOOST_REQUIRE_MESSAGE(input.to.size() == 20, std::string("address wrong: ") + evm_address);

        bytes calldata;
        uint8_t func[4] = {0x6a, 0x03, 0x66, 0xbf};  // sha3(egressFee())[:4] = 6a0366bf

        calldata.insert(calldata.end(), func, func + 4);

        input.data = calldata;

        auto res = exec(input, callback);

        BOOST_REQUIRE(res);
        BOOST_REQUIRE(res->action_traces.size() == 1);

        // Since callback information was not provided the result of the
        // execution is returned in the action return_value
        auto out = fc::raw::unpack<exec_output>(res->action_traces[0].return_value);
        BOOST_REQUIRE(out.status == 0);
        BOOST_REQUIRE(out.data.size() == 32);

        auto result = intx::be::unsafe::load<intx::uint256>(reinterpret_cast<const uint8_t*>(out.data.data()));
        return result;
    }

    intx::uint256 balanceOf(const char* owner, std::optional<exec_callback> callback = {}, std::optional<bytes> context = {}) {
        exec_input input;
        input.context = context;
        input.to = *erc20_test::from_hex(evm_address.c_str());

        bytes calldata;
        uint8_t func[4] = {0x70, 0xa0, 0x82, 0x31};  // sha3(balanceOf(address))[:4] = 70a08231

        calldata.insert(calldata.end(), func, func + 4);
        auto dest_buffer = erc20_test::from_hex(owner);
        uint8_t value_buffer[32] = {};
        memcpy(value_buffer + 32 - kAddressLength, dest_buffer->data(), kAddressLength);

        calldata.insert(calldata.end(), value_buffer, value_buffer + 32);

        input.data = calldata;

        auto res = exec(input, callback);

        BOOST_REQUIRE(res);
        BOOST_REQUIRE(res->action_traces.size() == 1);

        // Since callback information was not provided the result of the
        // execution is returned in the action return_value
        auto out = fc::raw::unpack<exec_output>(res->action_traces[0].return_value);
        BOOST_REQUIRE(out.status == 0);
        BOOST_REQUIRE(out.data.size() == 32);

        auto result = intx::be::unsafe::load<intx::uint256>(reinterpret_cast<const uint8_t*>(out.data.data()));
        return result;
    }

    void bridgeTransferERC20(evm_eoa& from, evmc::address& to, intx::uint256 amount, std::string memo, intx::uint256 egressfee) {
        auto target = evmc::from_hex<evmc::address>(evm_address);
        auto txn = generate_tx(*target, egressfee, 500'000);
        // bridgeTransfer(address,uint256,string) = 73761828
        txn.data = evmc::from_hex("0x73761828").value();
        txn.data += evmc::from_hex(address_str32(to)).value();       // param1 (to: address)
        txn.data += evmc::from_hex(uint256_str32(amount)).value();   // param2 (amount: uint256)
        txn.data += evmc::from_hex(int_str32(96)).value();           // offset memo (data: bytes)
        txn.data += evmc::from_hex(int_str32(memo.size())).value();  // memo length
        if (!memo.empty()) {
            txn.data += evmc::from_hex(data_str32(str_to_hex(memo))).value();  // memo
        }

        auto old_nonce = from.next_nonce;
        from.sign(txn);

        try {
            auto r = pushtx(txn);
            // dlog("action trace: ${a}", ("a", r));
        } catch (...) {
            from.next_nonce = old_nonce;
            throw;
        }
    }

    void transferERC20(evm_eoa& from, evmc::address& to, intx::uint256 amount) {
        auto target = evmc::from_hex<evmc::address>(evm_address);

        auto txn = generate_tx(*target, 0, 500'000);
        // transfer(address,uint256) = a9059cbb
        txn.data = evmc::from_hex("0xa9059cbb").value();
        txn.data += evmc::from_hex(address_str32(to)).value();      // param1 (to: address)
        txn.data += evmc::from_hex(uint256_str32(amount)).value();  // param2 (amount: uint256)

        auto old_nonce = from.next_nonce;
        from.sign(txn);

        try {
            auto r = pushtx(txn);
            // dlog("action trace: ${a}", ("a", r));
        } catch (...) {
            from.next_nonce = old_nonce;
            throw;
        }
    }
};

BOOST_AUTO_TEST_SUITE(erc20_tests)

BOOST_FIXTURE_TEST_CASE(it_basic_transfer, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());

    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);

    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));

    produce_block();

    auto fee = egressFee();
    // received = 1000/1e6*1e4 = 10
    bridgeTransferERC20(evm1, addr_alice, 1000, "aaa", fee);
    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());

    BOOST_REQUIRE(bal == 989000);
    bal = get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount();

    BOOST_REQUIRE(99990010 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_upgrade, it_tester)
try {

    

    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());

    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);

    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));

    produce_block();

    auto fee = egressFee();
    // received = 1000/1e6*1e4 = 10
    bridgeTransferERC20(evm1, addr_alice, 1000, "aaa", fee);
    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());

    BOOST_REQUIRE(bal == 989000);
    bal = get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount();

    BOOST_REQUIRE(99990010 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());

    // upgrade 

    evm_eoa deployer;
    evmc::address impl_addr = silkworm::create_address(deployer.address, deployer.next_nonce); 

    transfer_token(eos_token_account, faucet_account_name, evmin_account, make_asset(1000000, eos_token_symbol), deployer.address_0x().c_str());

    auto txn = prepare_deploy_contract_tx(solidity::erc20::bytecode, sizeof(solidity::erc20::bytecode), 10'000'000);

    deployer.sign(txn);
    pushtx(txn);
    produce_block();

    push_action(erc20_account, "upgradeto"_n, erc20_account, mvo()("impl_address",fc::variant(impl_addr).as_string()));

    produce_block();

    push_action(erc20_account, "callupgrade"_n, erc20_account, mvo()("proxy_address",evm_address.substr(2)));

    produce_block();

    // Perform some basic tests again

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    bal = balanceOf(evm1.address_0x().c_str());

    BOOST_REQUIRE(bal == 989000 + 990000);

    fee = egressFee();
    // received = 1000/1e6*1e4 = 10
    bridgeTransferERC20(evm1, addr_alice, 1000, "aaa", fee);
    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());

    BOOST_REQUIRE(bal == 989000 * 2);

}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_unregtoken, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());

    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);

    produce_block();

    // alice send 1.0000 USDT to evm1
    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    // evm1 has 0.990000 USDT
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 990000);

    // alice has 9999.0000 USDT
    BOOST_REQUIRE(9999'0000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());

    // unregtoken
    push_action(
        erc20_account, "unregtoken"_n, erc20_account, mvo()("eos_contract_name", token_account)("token_symbol_code", (std::string)(token_symbol.name())));

    // EOS->EVM not allowed after unregtoken
    BOOST_REQUIRE_EXCEPTION(
        transfer_token(token_account, "alice"_n, erc20_account, make_asset(20000, token_symbol), evm1.address_0x().c_str()),
        eosio_assert_message_exception, 
        eosio_assert_message_is("received unregistered token"));

    // EVM->EOS not allowed after unregtoken
    auto fee = egressFee();
    BOOST_REQUIRE_EXCEPTION(
        bridgeTransferERC20(evm1, addr_alice, 10000, "aaa", fee),
        eosio_assert_message_exception, 
        eosio_assert_message_is("ERC-20 token not registerred"));

    // register token again (imply a different ERC-EVM address)
    push_action(erc20_account, "regtoken"_n, erc20_account, mvo()("eos_contract_name",token_account.to_string())("evm_token_name","EVM USDT V2")("evm_token_symbol","WUSDT")("ingress_fee","0.0100 USDT")("egress_fee","0.0100 EOS")("erc20_precision",6));

    // EOS->EVM: alice transfer 2 USDT to evm1 in EVM (new ERC-EVM address)
    transfer_token(token_account, "alice"_n, erc20_account, make_asset(20000, token_symbol), evm1.address_0x().c_str());

    // alice has 9997.0000 USDT
    BOOST_REQUIRE(9997'0000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());

    // evm1 has 0.990000 USDT under the original ERC-20 address
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 990000);

    // refresh evm token address
    evm_address = getSolidityContractAddress();

    // evm1 has 1.990000 USDT under the new ERC-20 address
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 1990000);

    // EVM->EOS: evm1 tranfer 0.010000 USDT to alice
    bridgeTransferERC20(evm1, addr_alice, 10000, "aaa", fee);

    // evm1 has 1.980000 USDT under the new ERC-20 address
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 1980000);    

    // alice has 9997.0000 USDT
    BOOST_REQUIRE(9997'0100 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_eos_to_evm, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000); // +1000000 - 10000
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // -10000
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, erc20_account, make_asset(0, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("must transfer positive quantity"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();


    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, erc20_account, make_asset(10, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("deposit amount must be greater than ingress fee"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, erc20_account, make_asset(100, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("deposit amount must be greater than ingress fee"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(101, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990100); // 9900000 + (10100 - 10000)
    BOOST_REQUIRE(99989899 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 99990000 - 101
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9901, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(200, token_symbol));
    produce_block();

    // setting a lower gas limit, USDT(EOS)-> USDT(EVM) will fails
    push_action(erc20_account, "setgaslimit"_n, erc20_account, mvo("gaslimit", 21001)("init_gaslimit", 10000000));

    BOOST_REQUIRE_EXCEPTION(
        transfer_token(token_account, "alice"_n, erc20_account, make_asset(102, token_symbol), evm1.address_0x().c_str()),
        eosio_assert_message_exception, 
        eosio_assert_message_is("pre_validate_transaction error: 22 Intrinsic gas too low")
    );

    // set it back
    push_action(erc20_account, "setgaslimit"_n, erc20_account, mvo("gaslimit", 500000)("init_gaslimit", 10000000));
    transfer_token(token_account, "alice"_n, erc20_account, make_asset(103, token_symbol), evm1.address_0x().c_str());

}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_evm_to_eos, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000100, token_symbol), evm1.address_0x().c_str());
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 1000000000); // +1000010000 - 10000, 1000 USDT
    BOOST_REQUIRE(89999900 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    auto fee = egressFee();
    // received = 1000/1e6*1e4 = 10
    bridgeTransferERC20(evm1, addr_alice, 1000, "aaa", fee);
    BOOST_REQUIRE(999999000 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999910 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    BOOST_REQUIRE_EXCEPTION(bridgeTransferERC20(evm1, addr_alice, 0, "aaa", fee), 
                eosio_assert_message_exception, eosio_assert_message_is("bridge amount must be positive"));
    BOOST_REQUIRE(999999000 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999910 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    BOOST_REQUIRE_EXCEPTION(bridgeTransferERC20(evm1, addr_alice, 1, "aaa", fee), 
                eosio_assert_message_exception, eosio_assert_message_is("bridge amount can not have dust"));
    BOOST_REQUIRE(999999000 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999910 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    bridgeTransferERC20(evm1, addr_alice, 100, "aaa", fee);
    BOOST_REQUIRE(999998900 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999911 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    bridgeTransferERC20(evm1, addr_alice, 100, "aaa", fee+1); // revert
    BOOST_REQUIRE(999998900 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999911 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    bridgeTransferERC20(evm1, addr_alice, 100, "aaa", fee-1); // revert
    BOOST_REQUIRE(999998900 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999911 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();


}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_set_ingress_fee, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000100, token_symbol), evm1.address_0x().c_str());
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 1000000000); // +1000010000 - 10000, 1000 USDT
    BOOST_REQUIRE(89999900 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    BOOST_REQUIRE(10000100 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount()); 
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(10000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    push_action(erc20_account, "setingressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("ingress_fee", make_asset(200, token_symbol)));

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000200, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 2000000000); // 1000000000 +1000020000 - 20000, 2000 USDT
    BOOST_REQUIRE(79999700 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    BOOST_REQUIRE(20000300 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(20000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(300, token_symbol));
    produce_block();

    // Change fee and try transfer again.
    push_action(erc20_account, "setingressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("ingress_fee", make_asset(0, token_symbol)));

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000000, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 3000000000); // +1000000000
    BOOST_REQUIRE(69999700 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    BOOST_REQUIRE(30000300 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount()); 
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(30000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(300, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "setingressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("ingress_fee", make_asset(0, symbol::from_string("4,USDC"))));,
            eosio_assert_message_exception, eosio_assert_message_is("token not registered"));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "setingressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("ingress_fee", make_asset(0, symbol::from_string("2,USDT"))));,
            eosio_assert_message_exception, eosio_assert_message_is("incorrect precision for registered token"));

}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_set_egress_fee, it_tester)
try {
    constexpr intx::uint256 minimum_natively_representable = intx::exp(10_u256, intx::uint256(18 - 4));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "setegressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("token_symbol_code", "USDT")("egress_fee", make_asset(50))),
        eosio_assert_message_exception, eosio_assert_message_is("egress fee must be at least as large as the receiver's minimum fee"));

    produce_block();

    BOOST_REQUIRE(100 * minimum_natively_representable == egressFee()); // was 0.01

    produce_block();
    // set to 0.5
    push_action(erc20_account, "setegressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("token_symbol_code", "USDT")("egress_fee", make_asset(5000)));
    
    BOOST_REQUIRE(5000 * minimum_natively_representable == egressFee());

    produce_block();
   
    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "setegressfee"_n, evm_account, 
        mvo()("token_contract", token_account)("token_symbol_code", "USDT")("egress_fee", make_asset(1000))),
        missing_auth_exception, eosio::testing::fc_exception_message_starts_with("missing authority of eosio.erc2o"));


    produce_block();
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_withdraw_fees, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000100, token_symbol), evm1.address_0x().c_str());
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 1000000000); // +1000010000 - 10000, 1000 USDT
    BOOST_REQUIRE(89999900 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    BOOST_REQUIRE(10000100 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount()); 
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(10000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(10000, token_symbol))("to", "alice"_n)("memo", "asd")),
        eosio_assert_message_exception, eosio_assert_message_is("overdrawn balance"));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(0, token_symbol))("to", "alice"_n)("memo", "asd")),
        eosio_assert_message_exception, eosio_assert_message_is("quantity must be positive"));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(100, symbol::from_string("4,USDC")))("to", "alice"_n)("memo", "asd")),
        eosio_assert_message_exception, eosio_assert_message_is("token not registered"));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(100, symbol::from_string("2,USDT")))("to", "alice"_n)("memo", "asd")),
        eosio_assert_message_exception, eosio_assert_message_is("incorrect precision for registered token"));

    push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(100, token_symbol))("to", "alice"_n)("memo", "asd"));
    
    BOOST_REQUIRE(bal == 1000000000); // +1000010000 - 10000, 1000 USDT
    BOOST_REQUIRE(90000000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); 
    BOOST_REQUIRE(10000000 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount()); 
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(10000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(0, token_symbol));
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_eos_to_evm_with_proxy, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);
    produce_block();

    transfer_token(token_account, "alice"_n, evmin_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000); // +1000000 - 10000
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // -10000
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, evmin_account, make_asset(0, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("must transfer positive quantity"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();


    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, evmin_account, make_asset(10, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("deposit amount must be greater than ingress fee"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, evmin_account, make_asset(100, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("deposit amount must be greater than ingress fee"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    transfer_token(token_account, "alice"_n, evmin_account, make_asset(101, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990100); // 9900000 + (10100 - 10000)
    BOOST_REQUIRE(99989899 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 99990000 - 101
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9901, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(200, token_symbol));
    produce_block();

}
FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
