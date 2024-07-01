#include <variant>
#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

using namespace eosio;

namespace endrmng {

    class contract_actions {
        public:
        void evmstake(const checksum256& proxy, const checksum256& staker, const name& validator, const uint64_t quantity); 
        void evmunstake(const checksum256& proxy, const checksum256& staker, const name& validator, const uint64_t quantity);   
        void evmclaim(const checksum256& proxy, const checksum256& staker, const name& validator);  
    };

    using evmstake_action = action_wrapper<"evmstake"_n, &contract_actions::evmstake>;
    using evmunstake_action = action_wrapper<"evmunstake"_n, &contract_actions::evmunstake>;
    using evmclaim_action = action_wrapper<"evmclaim"_n, &contract_actions::evmclaim>;

}
