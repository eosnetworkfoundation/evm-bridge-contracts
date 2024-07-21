#include <variant>
#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

using namespace eosio;

namespace poolreg {

    class contract_actions {
        public:  
        /**
         * @brief add slot action.
         * @auth synchronizer->to or evmutil.xsat
         *
         * @param synchronizer - synchronizer account
         *
         */
        [[eosio::action]]
        void claim(const name& synchronizer);
    };

    using claim_action = action_wrapper<"claim"_n, &contract_actions::claim>;
}
