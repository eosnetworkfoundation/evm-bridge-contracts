#include <variant>
#include <eosio/asset.hpp>
#include <eosio/name.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>

using namespace eosio;

namespace stub {

inline std::string vec_to_hex(const checksum256& byte_array, bool with_prefix) {
    static const char* kHexDigits{"0123456789abcdef"};
    auto a = byte_array.extract_as_byte_array();
    std::string out(a.size() * 2 + (with_prefix ? 2 : 0), '\0');
    char* dest{&out[0]};
    if (with_prefix) {
        *dest++ = '0';
        *dest++ = 'x';
    }
    for (const auto& b : a) {
        *dest++ = kHexDigits[(uint8_t)b >> 4];    // Hi
        *dest++ = kHexDigits[(uint8_t)b & 0x0f];  // Lo
    }
    return out;
}

class [[eosio::contract]] stub_endrmng : public contract {
    using contract::contract;

    struct [[eosio::table("config")]] config_t {
        checksum160 proxy;
        std::vector<checksum160> stakers;
        name validator;
        std::map<checksum160, uint64_t> stakes;

        EOSLIB_SERIALIZE(config_t, (proxy)(stakers)(validator)(stakes));
    };
    typedef eosio::singleton<"config"_n, config_t> config_singleton_t;
    

    config_t get_config() const {
        config_singleton_t config(get_self(), get_self().value);
        eosio::check(config.exists(), "evmutil config not exist");
        return config.get();
    }
    
    void set_config(const config_t &v) {
        config_singleton_t config(get_self(), get_self().value);
        config.set(v, get_self());
    }

    bool stakerExists(const checksum160& staker) {
        config_t config = get_config();
        return std::find(config.stakers.begin(), config.stakers.end(), staker) != config.stakers.end();
    }

    public:
    /*
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
    

    /*
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

    /*
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

    /*
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
    [[eosio::action]] void reset(const checksum160& proxy, const checksum160& staker, const name& validator);
    [[eosio::action]] void assertstake(uint64_t stake, const checksum160& staker);
    [[eosio::action]] void assertval(const name& validator);
    [[eosio::action]] void addstaker(const checksum160& staker);
};

void stub_endrmng::evmstake(const name& caller, const checksum160& proxy, const checksum160& staker, const name& validator, const asset& quantity) {
    config_t config = get_config();

    check(proxy == config.proxy, "proxy not found");
    check(stakerExists(staker), "staker not found");
    check(validator == config.validator, "validator not found");
    config.stakes[staker] += quantity.amount;

    set_config(config);
    
}

void stub_endrmng::evmunstake(const name& caller, const checksum160& proxy, const checksum160& staker, const name& validator, const asset& quantity) {
    config_t config = get_config();
    
    check(proxy == config.proxy, "proxy not found");
    check(stakerExists(staker), "staker not found");
    check(validator == config.validator, "validator not found");
    check(config.stakes[staker] >= quantity.amount, "no enough stake");
    config.stakes[staker] -= quantity.amount;

    set_config(config);
}

void stub_endrmng::evmclaim(const name& caller, const checksum160& proxy, const checksum160& staker, const name& validator) {
    config_t config = get_config();
    
    check(proxy == config.proxy, "proxy not found" );
    check(stakerExists(staker), "staker not found");
    check(validator == config.validator, "validator not found");
    
    return;
}

void stub_endrmng::evmnewstake(const name& caller, const checksum160& proxy, const checksum160& staker, const name& validator, const name& new_validator, const asset& quantity) {
    config_t config = get_config();
    
    check(proxy == config.proxy, "proxy not found" );
    check(stakerExists(staker), "staker not found");
    check(validator == config.validator, "validator not found");
    config.validator = new_validator;
    set_config(config);
    return;
}

void stub_endrmng::reset(const checksum160& proxy, const checksum160& staker, const name& validator) {
 

    config_t config;

    config.proxy = proxy;
    config.validator = validator;

    if (config.stakes.find(staker) == config.stakes.end()) {
        config.stakers.push_back(staker);
    }
    config.stakes[staker] = 0;

    set_config(config);
}

void stub_endrmng::assertstake(uint64_t stake, const checksum160& staker) {
    config_t config = get_config();
    check(stake == config.stakes[staker], "stake not correct: " + std::to_string(stake) + " != " + std::to_string(config.stakes[staker]));
}
void stub_endrmng::addstaker(const checksum160& staker) {
    config_t config = get_config();
    if (config.stakes.find(staker) == config.stakes.end()) {
        config.stakes[staker] = 0;
        config.stakers.push_back(staker);
    }
    set_config(config);
}

void stub_endrmng::assertval(const name& validator) {
    config_t config = get_config();
    check(validator == config.validator, "validator not correct" );
}


}  // namespace stub

