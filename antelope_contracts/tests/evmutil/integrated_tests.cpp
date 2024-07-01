
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

#include "evmutil_tester.hpp"

using namespace eosio;
using namespace eosio::chain;
using namespace evmutil_test;
using namespace eosio::testing;
using mvo = fc::mutable_variant_object;

using intx::operator""_u256;
constexpr size_t kAddressLength{20};

struct it_tester : evmutil_tester {

    checksum256 make_key(const uint8_t *ptr, size_t len) {
        uint8_t buffer[32] = {};
        memcpy(buffer, ptr, len);
        return checksum256(buffer);
    }

    checksum256 make_key(bytes data) {
        return make_key((const uint8_t *)data.data(), data.size());
    }

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

    std::string xbtc_address;
    std::string stake_address;
    std::string reward_address;
    evm_eoa evm1;
    it_tester() : evmutil_tester(true) {
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

        xbtc_address = fc::variant(xbtc_addr).as_string();
        BOOST_REQUIRE_MESSAGE(xbtc_address.size() == 42, std::string("address wrong: ") + xbtc_address);

        stake_address = getSolidityContractAddress();
        BOOST_REQUIRE_MESSAGE(stake_address.size() == 42, std::string("address wrong: ") + stake_address);

        //reward_address = getSolidityContractAddress2();
        //BOOST_REQUIRE_MESSAGE(reward_address.size() == 42, std::string("address wrong: ") + reward_address);


        // init();

        auto proxy = evmc::from_hex<evmc::address>(stake_address);
        push_action(endrmng_account,
                    "reset"_n,
                    endrmng_account,
                    mvo()("proxy",make_key(proxy->bytes, 20))("staker",make_key(evm1.address.bytes, 20))("validator","alice"_n));
        produce_block();

    }

    std::string getSolidityContractAddress() {
        auto r = getRegistedTokenInfo();
        return vec_to_hex(r.address, true);
    }

    token_t getRegistedTokenInfo() {
        auto& db = const_cast<chainbase::database&>(control->db());

        const auto* existing_tid = db.find<table_id_object, by_code_scope_table>(
            boost::make_tuple(evmutil_account, evmutil_account, "tokens"_n));
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

    intx::uint256 balanceOf(const char* owner, std::optional<exec_callback> callback = {}, std::optional<bytes> context = {}) {
        exec_input input;
        input.context = context;
        input.to = *evmutil_test::from_hex(xbtc_address.c_str());

        bytes calldata;
        uint8_t func[4] = {0x70, 0xa0, 0x82, 0x31};  // sha3(balanceOf(address))[:4] = 70a08231

        calldata.insert(calldata.end(), func, func + 4);
        auto dest_buffer = evmutil_test::from_hex(owner);
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
        auto target = evmc::from_hex<evmc::address>(xbtc_address);
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

    intx::uint256 depFee(std::optional<exec_callback> callback = {}, std::optional<bytes> context = {}) {
        exec_input input;
        input.context = context;
        input.to = *evmutil_test::from_hex(stake_address.c_str());

        

        bytes calldata;
        uint8_t func[4] = {0x67, 0xa5, 0x27, 0x93};  // sha3(depositFee())[:4] = 67a52793

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

    void transferERC20(evm_eoa& from, evmc::address& to, intx::uint256 amount) {
        auto target = evmc::from_hex<evmc::address>(xbtc_address);

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

    void stake(evm_eoa& from, intx::uint256 amount, intx::uint256 fee) {
        auto target = evmc::from_hex<evmc::address>(stake_address);

        auto txn = generate_tx(*target, fee, 500'000);
        // deposit(address,uint256) = 47e7ef24
        txn.data = evmc::from_hex("0x47e7ef24").value();
        auto reserved_addr = silkworm::make_reserved_address("alice"_n.to_uint64_t());

        txn.data += evmc::from_hex(address_str32(reserved_addr)).value();      // param1 (to: address)
        txn.data += evmc::from_hex(uint256_str32(amount)).value();  // param2 (amount: uint256)

        auto old_nonce = from.next_nonce;
        from.sign(txn);

        try {
            auto r = pushtx(txn);
             dlog("action trace: ${a}", ("a", r));
        } catch (...) {
            from.next_nonce = old_nonce;
            throw;
        }
    }

    void withdraw(evm_eoa& from, intx::uint256 amount) {
        auto target = evmc::from_hex<evmc::address>(stake_address);

        auto txn = generate_tx(*target, 0, 500'000);
        // deposit(address,uint256) = f3fef3a3
        txn.data = evmc::from_hex("0xf3fef3a3").value();
        auto reserved_addr = silkworm::make_reserved_address("alice"_n.to_uint64_t());

        txn.data += evmc::from_hex(address_str32(reserved_addr)).value();      // param1 (to: address)
        txn.data += evmc::from_hex(uint256_str32(amount)).value();  // param2 (amount: uint256)

        auto old_nonce = from.next_nonce;
        from.sign(txn);

        try {
            auto r = pushtx(txn);
             dlog("action trace: ${a}", ("a", r));
        } catch (...) {
            from.next_nonce = old_nonce;
            throw;
        }
    }

    void approve(evm_eoa& from, intx::uint256 amount) {
        auto target = evmc::from_hex<evmc::address>(xbtc_address);
        auto spender = evmc::from_hex<evmc::address>(stake_address);

        auto txn = generate_tx(*target, 0, 500'000);
        // approve(address,uint256) = 095ea7b3
        txn.data = evmc::from_hex("0x095ea7b3").value();
        
        txn.data += evmc::from_hex(address_str32(*spender)).value();      // param1 (to: address)
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

BOOST_AUTO_TEST_SUITE(evmutil_tests)

BOOST_FIXTURE_TEST_CASE(it_xbtc_tests, it_tester)
try {
    
    

    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(100'0000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // XBTC balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);

    produce_block();
    auto token_addr = *evmc::from_hex<evmc::address>(xbtc_address);
    auto tx = generate_tx(token_addr, 1000,100000);
    evm1.sign(tx);
    pushtx(tx);

    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE_MESSAGE(bal == 1000, std::string("balance: ") + intx::to_string(bal));

    // TODO: transfer and withdraw
    evm_eoa evm2;

    transferERC20(evm1, evm2.address, 1000);

    produce_block();

    bal = balanceOf(evm2.address_0x().c_str());
    BOOST_REQUIRE_MESSAGE(bal == 1000, std::string("balance: ") + intx::to_string(bal));


    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE_MESSAGE(bal == 0, std::string("balance: ") + intx::to_string(bal));
}
FC_LOG_AND_RETHROW()



BOOST_FIXTURE_TEST_CASE(it_basic_stake, it_tester)
try {
    
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(100'0000, eos_token_symbol), evm1.address_0x().c_str());

    produce_block();
    auto token_addr = *evmc::from_hex<evmc::address>(xbtc_address);
    
    auto tx = generate_tx(token_addr, intx::exp(10_u256, intx::uint256(18))*2 ,10'0000);
    evm1.sign(tx);
    pushtx(tx);

    produce_block();

    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE_MESSAGE(bal == intx::exp(10_u256, intx::uint256(18))*2, std::string("balance: ") + intx::to_string(bal));


    approve(evm1, intx::exp(10_u256, intx::uint256(18)));
    produce_block();


    auto fee = depFee();
    produce_block();

    stake(evm1, intx::exp(10_u256, intx::uint256(18)), fee);
    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE_MESSAGE(bal == intx::exp(10_u256, intx::uint256(18)), std::string("balance: ") + intx::to_string(bal));

    produce_block();

    withdraw(evm1, intx::exp(10_u256, intx::uint256(18)));
    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE_MESSAGE(bal == intx::exp(10_u256, intx::uint256(18))*2, std::string("balance: ") + intx::to_string(bal));

    produce_block();
}
FC_LOG_AND_RETHROW()


BOOST_AUTO_TEST_SUITE_END()
