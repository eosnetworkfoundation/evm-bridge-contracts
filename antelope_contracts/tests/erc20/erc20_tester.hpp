#pragma once

#include <cstdint>
#include <cstring>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/fixed_bytes.hpp>
#include <eosio/testing/tester.hpp>
#include <intx/intx.hpp>
#include <optional>

namespace erc20_test {

typedef std::vector<char> bytes;

extern const eosio::chain::name eos_token_account;
extern const eosio::chain::symbol eos_token_symbol;
extern const eosio::chain::name token_account;
extern const eosio::chain::symbol token_symbol;
extern const eosio::chain::name evm_account;
extern const eosio::chain::name faucet_account_name;
extern const eosio::chain::name erc20_account;
extern const eosio::chain::name evmtok_account;
using namespace eosio;
using namespace eosio::chain;

class erc20_tester : public eosio::testing::base_tester {
   public:
    const eosio::chain::symbol native_symbol;
    explicit erc20_tester(std::string native_symbol_str = "4,EOS");

    eosio::chain::asset make_asset(int64_t amount) const { return eosio::chain::asset(amount, native_symbol); }
    eosio::chain::asset make_asset(int64_t amount, const eosio::chain::symbol& target_symbol) const { return eosio::chain::asset(amount, target_symbol); }
    eosio::chain::transaction_trace_ptr transfer_token(eosio::chain::name token_account_name, eosio::chain::name from, eosio::chain::name to, eosio::chain::asset quantity, std::string memo = "");

    eosio::chain::abi_serializer abi_ser;
    eosio::chain::abi_serializer token_abi_ser;

    eosio::chain::asset get_balance(const account_name& act, const account_name& token_addr, const eosio::chain::symbol& target_symbol) {
        std::vector<char> data = get_row_by_account(token_addr, act, "accounts"_n, name(target_symbol.to_symbol_code().value));
        return data.empty() ? eosio::chain::asset(0, target_symbol) : token_abi_ser.binary_to_variant("account", data, eosio::chain::abi_serializer::create_yield_function(abi_serializer_max_time))["balance"].as<eosio::chain::asset>();
    }

    using base_tester::produce_block;

    signed_block_ptr produce_block( fc::microseconds skip_time = fc::milliseconds(config::block_interval_ms) )override {
        return _produce_block(skip_time, false);
    }

    signed_block_ptr produce_empty_block( fc::microseconds skip_time = fc::milliseconds(config::block_interval_ms) )override {
        unapplied_transactions.add_aborted( control->abort_block() );
        return _produce_block(skip_time, true);
    }

    signed_block_ptr finish_block()override {
        return _finish_block();
    }
};

// Hex helper functions:
// Copied from EVMC: Ethereum Client-VM Connector API.
// No functionality modification expected.
// Copyright 2021 The EVMC Authors.
// Licensed under the Apache License, Version 2.0.

/// Extracts the nibble value out of a hex digit.
/// Returns -1 in case of invalid hex digit.
inline constexpr int from_hex_digit(char h) noexcept {
    if (h >= '0' && h <= '9')
        return h - '0';
    else if (h >= 'a' && h <= 'f')
        return h - 'a' + 10;
    else if (h >= 'A' && h <= 'F')
        return h - 'A' + 10;
    else
        return -1;
}

/// Decodes hex-encoded sequence of characters.
///
/// It is guaranteed that the output will not be longer than half of the input length.
///
/// @param begin  The input begin iterator. It only must satisfy input iterator concept.
/// @param end    The input end iterator. It only must satisfy input iterator concept.
/// @param out    The output iterator. It must satisfy output iterator concept.
/// @return       True if successful, false if input is invalid hex.
template <typename InputIt, typename OutputIt>
inline constexpr bool from_hex(InputIt begin, InputIt end, OutputIt out) noexcept {
    int hi_nibble = -1;  // Init with invalid value, should never be used.
    size_t i = 0;
    for (auto it = begin; it != end; ++it, ++i) {
        const auto h = *it;
        const int v = from_hex_digit(h);
        if (v < 0) {
            if (i == 1 && hi_nibble == 0 && h == 'x')  // 0x prefix
                continue;
            return false;
        }

        if (i % 2 == 0)
            hi_nibble = v << 4;
        else
            *out++ = static_cast<uint8_t>(hi_nibble | v);
    }

    return i % 2 == 0;
}

/// Decodes hex encoded string to bytes.
///
/// In case the input is invalid the returned value is std::nullopt.
/// This can happen if a non-hex digit or odd number of digits is encountered.
inline std::optional<bytes> from_hex(std::string_view hex) {
    bytes bs;
    bs.reserve(hex.size() / 2);
    if (!from_hex(hex.begin(), hex.end(), std::back_inserter(bs)))
        return {};
    return bs;
}

}  // namespace erc20_test
