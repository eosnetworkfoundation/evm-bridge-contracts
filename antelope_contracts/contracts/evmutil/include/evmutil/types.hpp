#pragma once

#include <eosio/eosio.hpp>
#include <intx/intx.hpp>

using namespace eosio;
using namespace intx;

namespace evmutil {

typedef std::vector<char> bytes;

constexpr size_t kAddressLength{20};
constexpr size_t kHashLength{32};
constexpr uint64_t default_evm_gaslimit = 500000;
constexpr uint64_t default_evm_init_gaslimit = 10000000;

constexpr eosio::name default_evm_account(eosio::name("evm.xsat"));
constexpr eosio::name default_endrmng_account(eosio::name("endrmng.xsat"));
constexpr eosio::name default_poolreg_account(eosio::name("poolreg.xsat"));

constexpr unsigned evm_precision = 18; // precision of native token(aka.EOS) in EVM side
constexpr eosio::symbol default_native_token_symbol("BTC", 8u);
constexpr eosio::symbol default_xsat_token_symbol("XSAT", 8u);

struct bridge_message_v0 {
        eosio::name receiver;
        bytes sender;
        eosio::time_point timestamp;
        bytes value;
        bytes data;

        EOSLIB_SERIALIZE(bridge_message_v0, (receiver)(sender)(timestamp)(value)(data));
    };

using bridge_message_t = std::variant<bridge_message_v0>;

checksum256 make_key(const uint8_t *ptr, size_t len) {
    uint8_t buffer[32] = {};
    check(len <= sizeof(buffer), "len provided to make_key is too small");
    memcpy(buffer, ptr, len);
    return checksum256(buffer);
}

checksum256 make_key(bytes data) {
    return make_key((const uint8_t *)data.data(), data.size());
}

checksum160 make_key160(const uint8_t *ptr, size_t len) {
    uint8_t buffer[20] = {};
    check(len <= sizeof(buffer), "len provided to make_key is too small");
    memcpy(buffer, ptr, len);
    return checksum160(buffer);
}

checksum160 make_key160(bytes data) {
    return make_key160((const uint8_t *)data.data(), data.size());
}

}  // namespace evmutil