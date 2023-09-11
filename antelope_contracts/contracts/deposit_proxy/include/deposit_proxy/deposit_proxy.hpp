#include <eosio/eosio.hpp>
#include <eosio/asset.hpp>
using namespace eosio;

CONTRACT deposit_proxy : public contract {
public:
   using contract::contract;

   [[eosio::on_notify("*::transfer")]]
   void transfer(eosio::name from, eosio::name to, eosio::asset quantity, const std::string& memo);
};