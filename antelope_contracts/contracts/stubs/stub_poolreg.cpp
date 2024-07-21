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

class [[eosio::contract]] stub_poolreg : public contract {
    using contract::contract;

    struct [[eosio::table("config")]] config_t {
        name synchronizer;

        EOSLIB_SERIALIZE(config_t, (synchronizer));
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

    [[eosio::action]] void claim(const name& synchronizer);  
    [[eosio::action]] void reset(const name& synchronizer);  
};



void stub_poolreg::claim(const name& synchronizer) {
    config_t config = get_config();
    
    check(synchronizer == config.synchronizer, "synchronizer not found");
    
    return;
}


void stub_poolreg::reset(const name& synchronizer) {
 

    config_t config;

    config.synchronizer = synchronizer;

    set_config(config);
}


}  // namespace stub

