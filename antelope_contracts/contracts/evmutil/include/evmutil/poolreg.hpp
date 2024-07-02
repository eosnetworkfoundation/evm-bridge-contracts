#include <variant>
#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

using namespace eosio;

namespace poolreg {

    class contract_actions {
        public:  
        void claim(const name& synchronizer);
    };

    using claim_action = action_wrapper<"claim"_n, &contract_actions::claim>;
}
