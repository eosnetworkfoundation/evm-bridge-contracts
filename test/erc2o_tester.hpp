#pragma once

#include <cstdint>
#include <cstring>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/fixed_bytes.hpp>
#include <eosio/testing/tester.hpp>
#include <intx/intx.hpp>
#include <optional>

extern const eosio::chain::name eos_token_account;
extern const eosio::chain::symbol eos_token_symbol;
extern const eosio::chain::name token_account;
extern const eosio::chain::symbol token_symbol;
extern const eosio::chain::name evm_account;
extern const eosio::chain::name faucet_account_name;
extern const eosio::chain::name erc2o_account;

class erc2o_tester : public eosio::testing::validating_tester {
   public:
    const eosio::chain::symbol native_symbol;
    explicit erc2o_tester(std::string native_symbol_str = "4,EOS");

    eosio::chain::asset make_asset(int64_t amount) const { return eosio::chain::asset(amount, native_symbol); }
    eosio::chain::transaction_trace_ptr transfer_token(eosio::chain::name token_account_name, eosio::chain::name from, eosio::chain::name to, eosio::chain::asset quantity, std::string memo = "");

};
