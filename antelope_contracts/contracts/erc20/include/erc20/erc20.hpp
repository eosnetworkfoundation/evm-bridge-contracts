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
    uint8_t buffer[32]={};
    check(len <= sizeof(buffer), "len provided to make_key is too small");
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
    [[eosio::action]] void upgrade();

    [[eosio::action]] void regtoken(eosio::name eos_contract_name, 
    std::string evm_token_name, std::string evm_token_symbol, const eosio::asset& ingress_fee, const eosio::asset &egress_fee, uint8_t erc20_precision);

    [[eosio::action]] void addegress(const std::vector<name>& accounts);
    [[eosio::action]] void removeegress(const std::vector<name>& accounts);
    [[eosio::action]] void setegressfee(eosio::name token_contract, eosio::symbol_code token_symbol_code, const eosio::asset &egress_fee);

   uint64_t get_next_nonce();

   struct nextnonce {
      name     owner;
      uint64_t next_nonce = 0;

      uint64_t primary_key() const { return owner.value; }
      EOSLIB_SERIALIZE(nextnonce, (owner)(next_nonce));
   };

   struct [[eosio::table("implcontract")]] impl_contract_t {
      uint64_t       id = 0;
      bytes          address;

      uint64_t       primary_key() const {
         return id;
      }
      EOSLIB_SERIALIZE(impl_contract_t, (id)(address));
   };
   typedef eosio::multi_index<"implcontract"_n, impl_contract_t> impl_contract_table_t;

   struct [[eosio::table("tokens")]] token_t {
      uint64_t       id = 0;
      eosio::name    token_contract; 
      bytes          address; // <-- proxy contract addr
      eosio::asset   ingress_fee;
      eosio::asset   balance; // <-- total amount in EVM side
      eosio::asset   fee_balance;
      uint8_t        erc20_precision = 0;

      uint64_t primary_key() const {
         return id;
      }
      uint128_t by_contract_symbol() const {
         uint128_t v = token_contract.value;
         v <<= 64;
         v |= ingress_fee.symbol.code().raw();
         return v;
      }
      checksum256 by_address()const { 
        return make_key(address);
      }

      EOSLIB_SERIALIZE(token_t, (id)(token_contract)(address)(ingress_fee)(balance)(fee_balance)(erc20_precision));
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

    void handle_erc20_transfer(const token_t &token, eosio::asset quantity, const std::string &memo);

    // actions defined in evm_runtime contract
    void call(eosio::name from, const bytes &to, const bytes& value, const bytes &data, uint64_t gas_limit);
    using call_action = action_wrapper<"call"_n, &erc20::call>;

    void assertnonce(eosio::name account, uint64_t next_nonce);
    using assertnonce_action = action_wrapper<"assertnonce"_n, &erc20::assertnonce>;


   struct  message_receiver {

      enum flag : uint32_t {
         FORCE_ATOMIC = 0x1
      };

      eosio::name     account;
      eosio::name     handler;
      eosio::asset    min_fee;
      uint32_t flags;

      uint64_t primary_key() const { return account.value; }
      bool has_flag(flag f) const {
         return (flags & f) != 0;
      }

      EOSLIB_SERIALIZE(message_receiver, (account)(handler)(min_fee)(flags));
   };

typedef eosio::multi_index<"msgreceiver"_n, message_receiver> message_receiver_table;


};

}  // namespace erc20