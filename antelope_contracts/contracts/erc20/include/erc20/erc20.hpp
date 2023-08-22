#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <intx/intx.hpp>
#include <erc20/types.hpp>

using namespace eosio;
using namespace intx;

namespace erc20 {

class [[eosio::contract]] erc20 : public contract {
   public:
    using contract::contract;

    [[eosio::on_notify("*::transfer")]] void transfer(eosio::name from, eosio::name to, eosio::asset quantity, std::string memo);

    // evm runtime will call this to notify erc20 about the message from 'from' with 'data'.
    [[eosio::action]] void onbridgemsg(name receiver, const bytes& sender, const time_point& timestamp, const bytes& value, const bytes& data);
    [[eosio::action]] void init();

    struct [[eosio::table]] [[eosio::contract("evm_contract")]] config
   {
      uint8_t erc20_addr[kAddressLength];
      EOSLIB_SERIALIZE(config, (erc20_addr));
   };

   private:

    eosio::singleton<"config"_n, config> _config{get_self(), get_self().value};
    void handle_evm_transfer(eosio::asset quantity, const std::string &memo);

    void call(eosio::name from, const bytes &to, uint128_t value, const bytes &data, uint64_t gas_limit);
    using call_action = action_wrapper<"call"_n, &erc20::call>;
};

}  // namespace erc20