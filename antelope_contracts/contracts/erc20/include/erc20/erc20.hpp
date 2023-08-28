#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <intx/intx.hpp>
#include <erc20/types.hpp>

using namespace eosio;
using namespace intx;

namespace erc20 {

checksum256 make_key(const uint8_t* ptr, size_t len) {
    uint8_t buffer[32]={0};
    check(len <= sizeof(buffer), "invalida size");
    memcpy(buffer, ptr, len);
    return checksum256(buffer);
}

checksum256 make_key(bytes data){
    return make_key((const uint8_t*)data.data(), data.size());
}

class [[eosio::contract]] erc20 : public contract {
   public:
    using contract::contract;

   struct bridge_message_v0 {
      eosio::name        receiver;
      bytes              sender;
      eosio::time_point  timestamp;
      bytes              value;
      bytes              data;

      EOSLIB_SERIALIZE(bridge_message_v0, (receiver)(sender)(timestamp)(value)(data));
   };

   using bridge_message_t = std::variant<bridge_message_v0>;

    [[eosio::on_notify("*::transfer")]] void transfer(eosio::name from, eosio::name to, eosio::asset quantity, std::string memo);

    // evm runtime will call this to notify erc20 about the message from 'from' with 'data'.
    [[eosio::action]] void onbridgemsg(const bridge_message_t &message);
    [[eosio::action]] void init(uint64_t nonce);

    [[eosio::action]] void regtoken(uint64_t nonce, eosio::name eos_contract_name, 
    std::string evm_token_name, std::string evm_token_symbol, const eosio::asset& min_deposit, const eosio::asset& deposit_fee, std::string erc20_impl_address, int erc20_precision);

    [[eosio::action]] void addegress(const std::vector<name>& accounts);
    [[eosio::action]] void removeegress(const std::vector<name>& accounts);

   struct [[eosio::table("implcontract")]] impl_contract_t {
      uint64_t       id = 0;
      bytes          address;

      uint64_t       primary_key() const {
         return id;
      }
      checksum256    by_address()const { 
        return make_key(address);
      }
   };
   typedef eosio::multi_index<"implcontract"_n, impl_contract_t,
      indexed_by<"by.address"_n, const_mem_fun<impl_contract_t,  checksum256, &impl_contract_t::by_address> > 
      > impl_contract_table_t;

   struct [[eosio::table("tokens")]] token_t {
      uint64_t       id = 0;
      eosio::name    eos_contract_name; 
      bytes          address; // <-- proxy contract addr
      eosio::asset   min_deposit;
      eosio::asset   deposit_fee;
      uint64_t       balance = 0; // <-- EVM side's balance
      int            erc20_precision = 0;

      uint64_t primary_key() const {
         return id;
      }
      uint128_t by_contract_symbol() const {
         uint128_t v = eos_contract_name.value;
         v <<= 64;
         v |= min_deposit.symbol.code().raw();
         return v;
      }
      checksum256 by_address()const { 
        return make_key(address);
      }

      EOSLIB_SERIALIZE(token_t, (id)(eos_contract_name)(address)(min_deposit)(deposit_fee)(balance)(erc20_precision));
   };
   typedef eosio::multi_index<"tokens"_n, token_t,
      indexed_by<"by.symbol"_n, const_mem_fun<token_t, uint128_t, &token_t::by_contract_symbol> >,
      indexed_by<"by.address"_n, const_mem_fun<token_t,  checksum256, &token_t::by_address> > 
      > token_table_t;

   struct [[eosio::table("egresslist")]] allowed_egress_account {
      eosio::name account;

      uint64_t primary_key() const { return account.value; }
      EOSLIB_SERIALIZE(allowed_egress_account, (account));
   };
   typedef eosio::multi_index<"egresslist"_n, allowed_egress_account> egresslist_table_t;

    struct [[eosio::table]] config
   {
      bytes    erc20_addr;
      EOSLIB_SERIALIZE(config, (erc20_addr));
   };

   private:

    eosio::singleton<"config"_n, config> _config{get_self(), get_self().value};
    void handle_erc20_transfer(const token_t &token, eosio::asset quantity, const std::string &memo);

    void call(eosio::name from, const bytes &to, const bytes& value, const bytes &data, uint64_t gas_limit);
    using call_action = action_wrapper<"call"_n, &erc20::call>;
};

}  // namespace erc20