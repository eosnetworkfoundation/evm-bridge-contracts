#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <evmutil/types.hpp>
#include <evmutil/tables.hpp>
#include <intx/intx.hpp>



using namespace eosio;
using namespace intx;

namespace evmutil {



class [[eosio::contract]] evmutil : public contract {
    public:
    using contract::contract;

    /**
     * @brief Default on transfer function. Will REJECT any token transfer in.
     * 
     * @auth None
     * 
     * @param from 
     * @param to 
     * @param quantity 
     * @param memo 
     */
    [[eosio::on_notify("*::transfer")]] void transfer(eosio::name from, eosio::name to, eosio::asset quantity, std::string memo);

    /**
     * @brief Message handler for bridge message from EVM
     * 
     * @auth Sender must be the EVM contract.
     * 
     * @param message 
     */
    [[eosio::action]] void onbridgemsg(const bridge_message_t &message);

    /**
     * @brief Deploy the implementation contract for stake helper in EVM. 
     *        Only works with certain leap configs. 
     *        Use setstakeimpl() instead when this action does not work.
     * 
     * @auth Self
     * 
     */
    [[eosio::action]] void dpystakeimpl();

    /**
     * @brief Set the default implementation for stake helper.
     * 
     * @auth Self
     * 
     * @param impl_address - The implementation address.
     */
    [[eosio::action]] void setstakeimpl(std::string impl_address);

    /**
     * @brief Deploy the contract for synchronizer reward helper in EVM. 
     *        Only works with certain leap configs. 
     *        Use setrwdhelper() instead when this action does not work.
     * 
     * @auth Self
     * 
     */
    [[eosio::action]] void dpyrwdhelper();

    /**
     * @brief Set the address of synchronizer reward helper.
     * 
     * @auth Self
     * 
     * @param impl_address - The implementation address.
     */
    [[eosio::action]] void setrwdhelper(std::string impl_address);

    /**
     * @brief Register an ERC20 token that wraps BTC. 
     *        Deploy a stake helper via proxy mapped to this token.
     *        The default implementation will be used.
     * 
     * @auth Self
     * 
     * @param token_address - The address of the ERC20 token.
     * @param dep_fee - Desired deposit fee.
     * @param erc20_precision - The precision of the ERC20 token.
     */
    [[eosio::action]] void regtoken(std::string token_address, const eosio::asset &dep_fee, uint8_t erc20_precision);

    /**
     * @brief Register an ERC20 token that wraps BTC. 
     *        Deploy a stake helper via proxy mapped to this token.
     *        Use the passing in implementation instead of the default one.
     * 
     * @auth Self
     * 
     * @param token_address - The address of the ERC20 token.
     * @param impl_address - The address of the implementation.
     * @param dep_fee - Desired deposit fee.
     * @param erc20_precision - The precision of the ERC20 token.
     */
    [[eosio::action]] void regwithcode(std::string token_address, std::string impl_address, const eosio::asset &dep_fee, uint8_t erc20_precision);

    /**
     * @brief Unregister an token.
     * 
     * @auth Self
     * 
     * @param proxy_address - The proxy address of the target stake helper.
     */
    [[eosio::action]] void unregtoken(std::string proxy_address);

    /**
     * @brief Initialize the contract.
     * 
     * @auth Self
     * 
     * @param evm_account - The account of the EVM contract.
     * @param gas_token_symbol - The symbol of the gas token. Should be same for both EVM and exSat.
     * @param gaslimit - The gas limit used when the contract calls EVM functions.
     * @param init_gaslimit - The gas limit used when the contract deploys EVM contracts.
     */
    [[eosio::action]] void init(eosio::name evm_account, eosio::symbol gas_token_symbol, uint64_t gaslimit, uint64_t init_gaslimit);
    
    /**
     * @brief Set deposit fee.
     * 
     * @auth Self
     * 
     * @param proxy_address - The proxy address for the targeting stake helper.
     * @param fee - New deposit fee.
     */
    [[eosio::action]] void setdepfee(std::string proxy_address, const eosio::asset &fee);

    /**
     * @brief Set gas limits.
     * 
     * @auth Self
     * 
     * @param gaslimit - The gas limit used when the contract calls EVM functions.
     * @param init_gaslimit - The gas limit used when the contract deploys EVM contracts.
     */
    [[eosio::action]] void setgaslimit(std::optional<uint64_t> gaslimit, std::optional<uint64_t> init_gaslimit);

    /**
     * @brief Set the lock time for stake helper.
     * 
     * @auth Self
     * 
     * @param proxy_address - The proxy address for the targeting stake helper.
     * @param locktime - The new lock time, in EVM blocks.
     */
    [[eosio::action]] void setlocktime(std::string proxy_address, uint64_t locktime);
    

    // Public Helpers
    config_t get_config() const;
    void set_config(const config_t &v);

    helpers_t get_helpers() const;
    void set_helpers(const helpers_t &v);

    intx::uint256 get_minimum_natively_representable(const config_t& config) const;
    uint64_t get_next_nonce();

private:

    // Private Helpers
    void regtokenwithcodebytes(const bytes& erc20_address_bytes, const bytes& impl_address_bytes, const eosio::asset& dep_fee, uint8_t erc20_precision);

    void handle_endorser_stakes(const bridge_message_v0 &msg, uint64_t delta_precision);
    void handle_utxo_access(const bridge_message_v0 &msg);
    void handle_rewards(const bridge_message_v0 &msg);

    eosio::name receiver_account()const;
};



}  // namespace evmutil