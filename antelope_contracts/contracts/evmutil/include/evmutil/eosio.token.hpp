#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <string>

namespace eosio {

using std::string;

class [[eosio::contract("eosio.token")]] token : public contract {
   public:
    using contract::contract;

    // All we care is transfer in this erc20 contract.
    [[eosio::action]] void transfer(const name& from,
                                    const name& to,
                                    const asset& quantity,
                                    const string& memo);

    using transfer_action = eosio::action_wrapper<"transfer"_n, &token::transfer>;
};
}  // namespace eosio
