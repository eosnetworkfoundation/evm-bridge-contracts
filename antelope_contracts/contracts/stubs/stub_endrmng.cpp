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
        checksum256 proxy;
        checksum256 staker;
        name validator;
        uint64_t stake;

        EOSLIB_SERIALIZE(config_t, (proxy)(staker)(validator)(stake));
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

    public:
    [[eosio::action]] void evmstake(const checksum256& proxy, const checksum256& staker, const name& validator, const uint64_t quantity); 
    [[eosio::action]] void evmunstake(const checksum256& proxy, const checksum256& staker, const name& validator, const uint64_t quantity);   
    [[eosio::action]] void evmclaim(const checksum256& proxy, const checksum256& staker, const name& validator);  
    [[eosio::action]] void reset(const checksum256& proxy, const checksum256& staker, const name& validator);  
    [[eosio::action]] void evmnewstake(const checksum256& proxy, const checksum256& staker, const name& validator, const name& new_validator);
};

void stub_endrmng::evmstake(const checksum256& proxy, const checksum256& staker, const name& validator, const uint64_t quantity) {
    config_t config = get_config();

    check(proxy == config.proxy, "proxy not found");
    check(staker == config.staker, "staker not found");
    check(validator == config.validator, "validator not found");
    config.stake += quantity;

    set_config(config);
    
}

void stub_endrmng::evmunstake(const checksum256& proxy, const checksum256& staker, const name& validator, const uint64_t quantity) {
    config_t config = get_config();
    
    check(proxy == config.proxy, "proxy not found");
    check(staker == config.staker, "staker not found");
    check(validator == config.validator, "validator not found");
    check(config.stake >= quantity, "no enough stake");
    config.stake -= quantity;

    set_config(config);
}

void stub_endrmng::evmclaim(const checksum256& proxy, const checksum256& staker, const name& validator) {
    config_t config = get_config();
    
    check(proxy == config.proxy, "proxy not found" );
    check(staker == config.staker, "staker not found");
    check(validator == config.validator, "validator not found");
    
    return;
}

void stub_endrmng::evmnewstake(const checksum256& proxy, const checksum256& staker, const name& validator, const name& new_validator) {
    config_t config = get_config();
    
    check(proxy == config.proxy, "proxy not found" );
    check(staker == config.staker, "staker not found");
    check(validator == config.validator, "validator not found");
    config.validator = new_validator;
    set_config(config);
    return;
}

void stub_endrmng::reset(const checksum256& proxy, const checksum256& staker, const name& validator) {
 

    config_t config;

    config.proxy = proxy;
    config.staker = staker;
    config.validator = validator;
    config.stake = 0;

    set_config(config);
}


}  // namespace stub

