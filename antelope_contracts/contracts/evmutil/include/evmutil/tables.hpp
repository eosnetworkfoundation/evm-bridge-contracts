#pragma once

#include <eosio/eosio.hpp>
#include <eosio/fixed_bytes.hpp>
#include <eosio/asset.hpp>
#include <eosio/singleton.hpp>
#include <eosio/binary_extension.hpp>

#include <evmutil/types.hpp>

namespace evmutil {

    struct [[eosio::table("implcontract")]] [[eosio::contract("evmutil")]] impl_contract_t {
        uint64_t id = 0;
        bytes address;

        uint64_t primary_key() const {
            return id;
        }
        EOSLIB_SERIALIZE(impl_contract_t, (id)(address));
    };
    typedef eosio::multi_index<"implcontract"_n, impl_contract_t> impl_contract_table_t;

    struct [[eosio::table("helpers")]] [[eosio::contract("evmutil")]] helpers_t {
        bytes reward_helper_address;
        binary_extension<bytes> btc_deposit_address;
        binary_extension<bytes> xsat_deposit_address;

        EOSLIB_SERIALIZE(helpers_t, (reward_helper_address)(btc_deposit_address)(xsat_deposit_address));
    };
    typedef eosio::singleton<"helpers"_n, helpers_t> helpers_singleton_t;
    struct [[eosio::table("tokens")]] [[eosio::contract("evmutil")]] token_t {
        uint64_t id = 0;
        bytes address;  // <-- proxy contract addr
        bytes token_address;  // <-- erc20 token contract addr
        uint8_t erc20_precision = 0;

        uint64_t primary_key() const {
            return id;
        }
        checksum256 by_address() const {
            return make_key(address);
        }
        checksum256 by_token_address() const {
            return make_key(token_address);
        }
        EOSLIB_SERIALIZE(token_t, (id)(address)(token_address)(erc20_precision));
    };
    typedef eosio::multi_index<"tokens"_n, token_t,
                               indexed_by<"by.tokenaddr"_n, const_mem_fun<token_t, checksum256, &token_t::by_token_address> >,
                               indexed_by<"by.address"_n, const_mem_fun<token_t, checksum256, &token_t::by_address> > >
        token_table_t;

    struct [[eosio::table("config")]] [[eosio::contract("evmutil")]] config_t {
        uint64_t      evm_gaslimit = default_evm_gaslimit;
        uint64_t      evm_init_gaslimit = default_evm_init_gaslimit;
        eosio::name   evm_account = default_evm_account;
        eosio::symbol evm_gas_token_symbol = default_native_token_symbol;
        eosio::name   endrmng_account = default_endrmng_account;
        eosio::name   poolreg_account = default_poolreg_account;

        EOSLIB_SERIALIZE(config_t, (evm_gaslimit)(evm_init_gaslimit)(evm_account)(evm_gas_token_symbol)(endrmng_account)(poolreg_account));
    };
    typedef eosio::singleton<"config"_n, config_t> config_singleton_t;

} // namespace evmutil
