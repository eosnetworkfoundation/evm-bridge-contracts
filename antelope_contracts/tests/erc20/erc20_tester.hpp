#pragma once

#include <cstdint>
#include <cstring>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/fixed_bytes.hpp>
#include <eosio/testing/tester.hpp>
#include <fc/crypto/hex.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/variant_object.hpp>
#include <fc/io/raw.hpp>
#include <intx/intx.hpp>
#include <optional>

#include <silkworm/core/types/transaction.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/address.hpp>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <silkworm/core/common/util.hpp>

namespace intx {

inline std::ostream& operator<<(std::ostream& ds, const intx::uint256& num)
{
   ds << intx::to_string(num, 10);
   return ds;
}

} // namespace intx

namespace fc {

void to_variant(const intx::uint256& o, fc::variant& v);
void to_variant(const evmc::address& o, fc::variant& v);
} // namespace fc

namespace erc20_test {

typedef std::vector<char> bytes;

struct exec_input {
   std::optional<bytes> context;
   std::optional<bytes> from;
   bytes                to;
   bytes                data;
   std::optional<bytes> value;
};

struct exec_callback {
   eosio::chain::name contract;
   eosio::chain::name action;
};

struct exec_output {
   int32_t              status;
   bytes                data;
   std::optional<bytes> context;
};

struct token_t {
        uint64_t id = 0;
        eosio::chain::name token_contract{};
        bytes address;  // <-- proxy contract addr
        eosio::chain::asset ingress_fee{};
        eosio::chain::asset balance{};  // <-- total amount in EVM side
        eosio::chain::asset fee_balance{};
        uint8_t erc20_precision = 0;

    };

} // namespace erc20_test

FC_REFLECT(erc20_test::exec_input, (context)(from)(to)(data)(value))
FC_REFLECT(erc20_test::exec_callback, (contract)(action))
FC_REFLECT(erc20_test::exec_output, (status)(data)(context))
FC_REFLECT(erc20_test::token_t, (id)(token_contract)(address)(ingress_fee)(balance)(fee_balance)(erc20_precision))

namespace erc20_test {
extern const eosio::chain::symbol eos_token_symbol;
extern const eosio::chain::symbol token_symbol;

class evm_eoa
{
public:
   explicit evm_eoa(std::basic_string<uint8_t> optional_private_key = {});

   std::string address_0x() const;

   eosio::chain::key256_t address_key256() const;

   void sign(silkworm::Transaction& trx);
   void sign(silkworm::Transaction& trx, std::optional<uint64_t> chain_id);

   ~evm_eoa();

   evmc::address address;
   uint64_t next_nonce = 0;

private:
   secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
   std::array<uint8_t, 32> private_key;
   std::basic_string<uint8_t> public_key;
};

constexpr uint64_t evm_chain_id = 15555;

   // Sensible values for fee parameters passed into init:
constexpr uint64_t suggested_gas_price = 150'000'000'000;    // 150 gwei
constexpr uint32_t suggested_miner_cut = 10'000;             // 10%
constexpr uint64_t suggested_ingress_bridge_fee_amount = 70; // 0.0070 EOS

extern const eosio::chain::name faucet_account_name;
extern const eosio::chain::name erc20_account;
extern const eosio::chain::name evmin_account;

using namespace eosio;
using namespace eosio::chain;

class erc20_tester : public eosio::testing::base_tester {
   public:
   using testing::base_tester::push_action;

   static constexpr eosio::chain::name token_account = "tethertether"_n;
    
   static constexpr eosio::chain::name faucet_account_name = "eosio.faucet"_n;
   static constexpr eosio::chain::name erc20_account = "eosio.erc2o"_n;
   static constexpr eosio::chain::name eos_system_account = "eosio"_n;
   const eosio::chain::name eos_token_account;

    const eosio::chain::name evm_account;
    const eosio::chain::symbol native_symbol;
    explicit erc20_tester(bool use_real_evm = false, eosio::chain::name evm_account_ = "eosio.evm"_n, std::string native_symbol_str = "4,EOS", eosio::chain::name eos_token_account_ = "eosio.token"_n);

    unsigned int exec_count = 0; // ensure uniqueness in exec

    eosio::chain::asset make_asset(int64_t amount) const { return eosio::chain::asset(amount, native_symbol); }
    eosio::chain::asset make_asset(int64_t amount, const eosio::chain::symbol& target_symbol) const { return eosio::chain::asset(amount, target_symbol); }
    eosio::chain::transaction_trace_ptr transfer_token(eosio::chain::name token_account_name, eosio::chain::name from, eosio::chain::name to, eosio::chain::asset quantity, std::string memo = "");
    void prepare_self_balance(uint64_t fund_amount = 100'0000);
    transaction_trace_ptr bridgereg(eosio::chain::name receiver, eosio::chain::name handler, eosio::chain::asset min_fee, vector<account_name> extra_signers={ ""_n /* default value replaced with evm_account*/});
    void open(name owner);
    transaction_trace_ptr exec(const exec_input& input, const std::optional<exec_callback>& callback);
    eosio::chain::action get_action( account_name code, action_name acttype, std::vector<permission_level> auths,
                                 const bytes& data )const;

    transaction_trace_ptr push_action( const account_name& code,
                                      const action_name& acttype,
                                      const account_name& actor,
                                      const bytes& data,
                                      uint32_t expiration = DEFAULT_EXPIRATION_DELTA,
                                      uint32_t delay_sec = 0 );
    
    silkworm::Transaction
    generate_tx(const evmc::address& to, const intx::uint256& value, uint64_t gas_limit = 21000) const;
    silkworm::Transaction
    prepare_deploy_contract_tx(const unsigned char* contract, size_t size, uint64_t gas_limit) const;
    transaction_trace_ptr pushtx(const silkworm::Transaction& trx, name miner = {});

    eosio::chain::abi_serializer abi_ser;
    eosio::chain::abi_serializer token_abi_ser;

    eosio::chain::asset get_balance(const account_name& act, const account_name& token_addr, const eosio::chain::symbol& target_symbol) {
        std::vector<char> data = get_row_by_account(token_addr, act, "accounts"_n, name(target_symbol.to_symbol_code().value));
        return data.empty() ? eosio::chain::asset(0, target_symbol) : token_abi_ser.binary_to_variant("account", data, eosio::chain::abi_serializer::create_yield_function(abi_serializer_max_time))["balance"].as<eosio::chain::asset>();
    }

    using base_tester::produce_block;

    signed_block_ptr produce_block( fc::microseconds skip_time = fc::milliseconds(config::block_interval_ms), bool no_throw = false )override {
        auto produce_block_result = _produce_block(skip_time, false, no_throw);
        auto sb = produce_block_result.block;
        return sb;
    }

    signed_block_ptr produce_empty_block( fc::microseconds skip_time = fc::milliseconds(config::block_interval_ms) )override {
        unapplied_transactions.add_aborted( control->abort_block() );
        auto sb = _produce_block(skip_time, true);
        return sb;
    }

    testing::produce_block_result_t produce_block_ex( fc::microseconds skip_time = default_skip_time, bool no_throw = false ) override {
        auto produce_block_result = _produce_block(skip_time, false, no_throw);
        return produce_block_result;
    }

    signed_block_ptr finish_block()override {
        return _finish_block();
    }

    void init_evm(const uint64_t chainid = evm_chain_id,
             const uint64_t gas_price = suggested_gas_price,
             const uint32_t miner_cut = suggested_miner_cut,
             const std::optional<asset> ingress_bridge_fee = std::nullopt,
             const bool also_prepare_self_balance = true);

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

inline std::string vec_to_hex(bytes byte_array, bool with_prefix) {
    static const char* kHexDigits{"0123456789abcdef"};
    std::string out(byte_array.size() * 2 + (with_prefix ? 2 : 0), '\0');
    char* dest{&out[0]};
    if (with_prefix) {
        *dest++ = '0';
        *dest++ = 'x';
    }
    for (const auto& b : byte_array) {
        *dest++ = kHexDigits[(uint8_t)b >> 4];    // Hi
        *dest++ = kHexDigits[(uint8_t)b & 0x0f];  // Lo
    }
    return out;
}

}  // namespace erc20_test
