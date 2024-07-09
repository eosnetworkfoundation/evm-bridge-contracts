#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <evmutil/types.hpp>
#include <intx/intx.hpp>

using namespace eosio;
using namespace intx;

namespace evmutil {

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

class [[eosio::contract]] evmutil : public contract {
    public:
    using contract::contract;

    struct bridge_message_v0 {
        eosio::name receiver;
        bytes sender;
        eosio::time_point timestamp;
        bytes value;
        bytes data;

        EOSLIB_SERIALIZE(bridge_message_v0, (receiver)(sender)(timestamp)(value)(data));
    };

    using bridge_message_t = std::variant<bridge_message_v0>;

    [[eosio::on_notify("*::transfer")]] void transfer(eosio::name from, eosio::name to, eosio::asset quantity, std::string memo);

    // evm runtime will call this to notify evmutil about the message from 'from' with 'data'.
    [[eosio::action]] void onbridgemsg(const bridge_message_t &message);
    [[eosio::action]] void deployimpls();
    [[eosio::action]] void deployhelper();
    [[eosio::action]] void setutilimpl(std::string impl_address);
    [[eosio::action]] void setstakeimpl(std::string impl_address);

    [[eosio::action]] void regtoken(std::string token_address, const eosio::asset &dep_fee, uint8_t erc20_precision);

    [[eosio::action]] void regwithcode(std::string token_address, std::string impl_address, const eosio::asset &dep_fee, uint8_t erc20_precision);
    [[eosio::action]] void setdepfee(std::string proxy_address, const eosio::asset &fee);
    [[eosio::action]] void unregtoken(std::string proxy_address);

    [[eosio::action]] void init(eosio::name evm_account, eosio::symbol gas_token_symbol, uint64_t gaslimit, uint64_t init_gaslimit);

    [[eosio::action]] void setgaslimit(std::optional<uint64_t> gaslimit, std::optional<uint64_t> init_gaslimit);
    [[eosio::action]] void setlocktime(std::string proxy_address, uint64_t locktime);
    struct [[eosio::table("implcontract")]] impl_contract_t {
        uint64_t id = 0;
        bytes address;

        uint64_t primary_key() const {
            return id;
        }
        EOSLIB_SERIALIZE(impl_contract_t, (id)(address));
    };
    typedef eosio::multi_index<"implcontract"_n, impl_contract_t> impl_contract_table_t;

    struct [[eosio::table("utilcontract")]] util_contract_t {
        uint64_t id = 0;
        bytes address;

        uint64_t primary_key() const {
            return id;
        }
        EOSLIB_SERIALIZE(util_contract_t, (id)(address));
    };
    typedef eosio::multi_index<"utilcontract"_n, util_contract_t> util_contract_table_t;

    struct [[eosio::table("tokens")]] token_t {
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

    struct [[eosio::table("config")]] config_t {
        uint64_t      evm_gaslimit = default_evm_gaslimit;
        uint64_t      evm_init_gaslimit = default_evm_init_gaslimit;
        eosio::name   evm_account = default_evm_account;
        eosio::symbol evm_gas_token_symbol = default_native_token_symbol;
        eosio::name   endrmng_account = default_endrmng_account;
        eosio::name   poolreg_account = default_poolreg_account;

        EOSLIB_SERIALIZE(config_t, (evm_gaslimit)(evm_init_gaslimit)(evm_account)(evm_gas_token_symbol)(endrmng_account)(poolreg_account));
    };
    typedef eosio::singleton<"config"_n, config_t> config_singleton_t;

    config_t get_config() const {
        config_singleton_t config(get_self(), get_self().value);
        eosio::check(config.exists(), "evmutil config not exist");
        return config.get();
    }

    intx::uint256 get_minimum_natively_representable(const config_t& config) const {
        return intx::exp(10_u256, intx::uint256(evm_precision - config.evm_gas_token_symbol.precision()));
    }
    
    void set_config(const config_t &v) {
        config_singleton_t config(get_self(), get_self().value);
        config.set(v, get_self());
    }

    uint64_t get_next_nonce();

private:
    void regtokenwithcodebytes(const bytes& erc20_address_bytes, const bytes& impl_address_bytes, const eosio::asset& dep_fee, uint8_t erc20_precision);

    void handle_endorser_stakes(const bridge_message_v0 &msg, uint64_t delta_precision);
    void handle_utxo_access(const bridge_message_v0 &msg);
    void handle_sync_rewards(const bridge_message_v0 &msg);

    eosio::name receiver_account()const;
};



}  // namespace evmutil