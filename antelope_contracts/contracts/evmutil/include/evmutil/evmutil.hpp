#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <evmutil/types.hpp>
#include <evmutil/tables.hpp>
#include <intx/intx.hpp>



using namespace eosio;
using namespace intx;

namespace evmutil {



class [[eosio::contract]] evmutil : public contract {
    public:
    using contract::contract;

    [[eosio::on_notify("*::transfer")]] void transfer(eosio::name from, eosio::name to, eosio::asset quantity, std::string memo);

    // evm runtime will call this to notify evmutil about the message from 'from' with 'data'.
    [[eosio::action]] void onbridgemsg(const bridge_message_t &message);

    [[eosio::action]] void dpystakeimpl();
    [[eosio::action]] void setstakeimpl(std::string impl_address);


    [[eosio::action]] void dpyrwdhelper();
    [[eosio::action]] void setrwdhelper(std::string impl_address);

    [[eosio::action]] void regtoken(std::string token_address, const eosio::asset &dep_fee, uint8_t erc20_precision);
    [[eosio::action]] void regwithcode(std::string token_address, std::string impl_address, const eosio::asset &dep_fee, uint8_t erc20_precision);
    [[eosio::action]] void unregtoken(std::string proxy_address);


    [[eosio::action]] void init(eosio::name evm_account, eosio::symbol gas_token_symbol, uint64_t gaslimit, uint64_t init_gaslimit);

    [[eosio::action]] void setdepfee(std::string proxy_address, const eosio::asset &fee);
    [[eosio::action]] void setgaslimit(std::optional<uint64_t> gaslimit, std::optional<uint64_t> init_gaslimit);
    [[eosio::action]] void setlocktime(std::string proxy_address, uint64_t locktime);
    
    config_t get_config() const;
    void set_config(const config_t &v);

    helpers_t get_helpers() const;
    void set_helpers(const helpers_t &v);

    intx::uint256 get_minimum_natively_representable(const config_t& config) const;
    uint64_t get_next_nonce();

private:
    void regtokenwithcodebytes(const bytes& erc20_address_bytes, const bytes& impl_address_bytes, const eosio::asset& dep_fee, uint8_t erc20_precision);

    void handle_endorser_stakes(const bridge_message_v0 &msg, uint64_t delta_precision);
    void handle_utxo_access(const bridge_message_v0 &msg);
    void handle_sync_rewards(const bridge_message_v0 &msg);

    eosio::name receiver_account()const;
};



}  // namespace evmutil