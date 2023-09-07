
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

        BOOST_REQUIRE(!evm_address.empty());
        // init();
    }
    intx::uint256 egressFee(std::optional<exec_callback> callback = {}, std::optional<bytes> context = {}) {
        exec_input input;
        input.context = context;
        input.to = *erc20_test::from_hex(evm_address.c_str());

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
        from.sign(txn);
        auto r = pushtx(txn);
        // dlog("action trace: ${a}", ("a", r));
    }

    void transferERC20(evm_eoa& from, evmc::address& to, intx::uint256 amount) {
        auto target = evmc::from_hex<evmc::address>(evm_address);

        auto txn = generate_tx(*target, 0, 500'000);
        // transfer(address,uint256) = a9059cbb
        txn.data = evmc::from_hex("0xa9059cbb").value();
        txn.data += evmc::from_hex(address_str32(to)).value();      // param1 (to: address)
        txn.data += evmc::from_hex(uint256_str32(amount)).value();  // param2 (amount: uint256)

        from.sign(txn);
        auto r = pushtx(txn);
        // dlog("action trace: ${a}", ("a", r));
    }
};

BOOST_AUTO_TEST_SUITE(erc20_tests)

BOOST_FIXTURE_TEST_CASE(verify_initialization, it_tester)
try {
    evm_eoa evm1;
    evm_eoa evm2;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());

    auto fee = egressFee();
    BOOST_TEST_MESSAGE(intx::to_string(fee));

    // Give some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();

    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);

    produce_block();

    transfer_token(token_account, "alice"_n, evmtok_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());

    produce_block();

    // received = 1000/1e6*1e4 = 10
    bridgeTransferERC20(evm1, addr_alice, 1000, "aaa", fee);
    // auto evm2_addr = evmc::from_hex<evmc::address>(evm2.address_0x());
    // transferERC20(evm1, *evm2_addr, 1000);
    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_TEST_MESSAGE(intx::to_string(bal));
    BOOST_REQUIRE(bal == 989000);
    bal = get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount();
    BOOST_TEST_MESSAGE(intx::to_string(bal));
    BOOST_REQUIRE(99990010 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
}
FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
