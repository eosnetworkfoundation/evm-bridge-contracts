#include <eosio/symbol.hpp>
#include <deposit_proxy/deposit_proxy.hpp>

void deposit_proxy::transfer(eosio::name from, eosio::name to, eosio::asset quantity, const std::string& memo) {

   if (to != get_self() || from == get_self()) return;

   constexpr extended_symbol EOS  = eosio::extended_symbol{eosio::symbol{"EOS",4}, "eosio.token"_n};
   constexpr extended_symbol USDT = eosio::extended_symbol{eosio::symbol{"USDT",4}, "tethertether"_n};

   const auto s = eosio::extended_symbol{quantity.symbol, get_first_receiver()};
   eosio::check(s == EOS || s == USDT, "unregistered token");

   bool memo_has_evm_address = false;
   if (memo.size() == 42 && memo[0] == '0' && memo[1] == 'x') {
      memo_has_evm_address = std::all_of(memo.begin() + 2, memo.end(), [](char c) {
         return (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F');
      });
   }

   eosio::check(memo_has_evm_address, "memo must be a valid EVM address");

   auto destination = s == EOS ? "eosio.evm"_n : "eosio.erc2o"_n;
   action(std::vector<permission_level>{{get_self(), "active"_n}}, s.get_contract(), "transfer"_n,
      std::make_tuple(get_self(), destination, quantity, memo)
   ).send();

}
