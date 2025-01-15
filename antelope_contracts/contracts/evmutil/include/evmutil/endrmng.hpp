#include <variant>
#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

using namespace eosio;

namespace endrmng {

    class contract_actions {
        public:
        /**
        * Evm stake action.
        * @auth scope is `evmcaller` whitelist account
        *
        * @param caller - the account that calls the method
        * @param proxy - proxy address
        * @param staker - staker address
        * @param validator - validator address
        * @param quantity - total number of stake
        *
        */
        [[eosio::action]]
        void evmstake(const name& caller, const checksum160& proxy, const checksum160& staker, const name& validator,
                    const asset& quantity);
        

        /**
        * Evm unstake action.
        * @auth scope is evmcaller whitelist account
        *
        * @param caller - the account that calls the method
        * @param proxy - proxy address
        * @param staker - staker address
        * @param validator - validator address
        * @param quantity - cancel pledge quantity
        *
        */
        [[eosio::action]]
        void evmunstake(const name& caller, const checksum160& proxy, const checksum160& staker, const name& validator,
                        const asset& quantity);

        /**
        * Evm change stake action.
        * @auth scope is `evmcaller` whitelist account
        *
        * @param caller - the account that calls the method
        * @param proxy - proxy address
        * @param staker - staker address
        * @param old_validator - old validator address
        * @param new_validator - new validator address
        * @param quantity - change the amount of pledge
        *
        */
        [[eosio::action]]
        void evmnewstake(const name& caller, const checksum160& proxy, const checksum160& staker, const name& old_validator,
                        const name& new_validator, const asset& quantity);

        /**
        * Evm stake action for XSAT.
        * @auth scope is `evmcaller` whitelist account
        *
        * @param caller - the account that calls the method
        * @param proxy - proxy address
        * @param staker - staker address
        * @param validator - validator address
        * @param quantity - total number of stake
        *
        */
        [[eosio::action]]
        void evmstakexsat(const name& caller, const checksum160& proxy, const checksum160& staker, const name& validator,
                    const asset& quantity);


        /**
        * Evm unstake action for XSAT.
        * @auth scope is evmcaller whitelist account
        *
        * @param caller - the account that calls the method
        * @param proxy - proxy address
        * @param staker - staker address
        * @param validator - validator address
        * @param quantity - cancel pledge quantity
        *
        */
        [[eosio::action]]
        void evmunstkxsat(const name& caller, const checksum160& proxy, const checksum160& staker, const name& validator,
                        const asset& quantity);

        /**
        * Evm claim reward action.
        * @auth scope is evmcaller whitelist account
        *
        * @param caller - the account that calls the method
        * @param proxy - proxy address
        * @param staker - staker address
        * @param validator - validator address
        *
        */
        [[eosio::action]]
        void evmclaim(const name& caller, const checksum160& proxy, const checksum160& staker, const name& validator);

        /**
         * validator claim reward action.
         * @auth validator->reward_recipient or evmutil.xsat
         *
         * @param validator - validator account
         *
         */
        [[eosio::action]]
        void vdrclaim(const name& validator);

    };

    using evmstake_action = action_wrapper<"evmstake"_n, &contract_actions::evmstake>;
    using evmunstake_action = action_wrapper<"evmunstake"_n, &contract_actions::evmunstake>;
    using evmclaim_action = action_wrapper<"evmclaim"_n, &contract_actions::evmclaim>;
    using evmnewstake_action = action_wrapper<"evmnewstake"_n, &contract_actions::evmnewstake>;
    using vdrclaim_action = action_wrapper<"vdrclaim"_n, &contract_actions::vdrclaim>;

    using evmstakexsat_action = action_wrapper<"evmstakexsat"_n, &contract_actions::evmstakexsat>;
    using evmunstkxsat_action = action_wrapper<"evmunstkxsat"_n, &contract_actions::evmunstkxsat>;
}
