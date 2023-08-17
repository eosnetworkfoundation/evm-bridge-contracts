#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

using namespace eosio;

namespace stub {

typedef std::vector<char> bytes;

class [[eosio::contract]] stub_evm_runtime : public contract {
    using contract::contract;

   public:
    [[eosio::action]] void call(eosio::name from, const bytes& to, uint128_t value, const bytes& data, uint64_t gas_limit);
    [[eosio::action]] void sendbridgemsg(eosio::name receiver, const bytes& sender, const eosio::time_point& timestamp, const bytes& value, const bytes& data);

   private:
    void onbridgemsg(name receiver, const bytes& sender, const time_point& timestamp, const bytes& value, const bytes& data);
    using onbridgemsg_action = action_wrapper<"onbridgemsg"_n, &stub_evm_runtime::onbridgemsg>;
};

void stub_evm_runtime::call(eosio::name from, const bytes& to, uint128_t value, const bytes& data, uint64_t gas_limit) {
}

void stub_evm_runtime::sendbridgemsg(eosio::name receiver, const bytes& sender, const eosio::time_point& timestamp, const bytes& value, const bytes& data) {
    onbridgemsg_action onbridgemsg_act(eosio::name("eosio.erc2o"), {{get_self(), "active"_n}});
    onbridgemsg_act.send(receiver, sender, timestamp, value, data);
}

}  // namespace stub