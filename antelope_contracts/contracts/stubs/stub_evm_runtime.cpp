#include <variant>
#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

using namespace eosio;

namespace stub {

typedef std::vector<char> bytes;

struct bridge_message_v0 {
    eosio::name        receiver;
    bytes              sender;
    eosio::time_point  timestamp;
    bytes              value;
    bytes              data;

    EOSLIB_SERIALIZE(bridge_message_v0, (receiver)(sender)(timestamp)(value)(data));
};

using bridge_message_t = std::variant<bridge_message_v0>;

class [[eosio::contract]] stub_evm_runtime : public contract {
    using contract::contract;

   public:
    [[eosio::action]] void call(eosio::name from, const bytes& to, uint128_t value, const bytes& data, uint64_t gas_limit);
    [[eosio::action]] void sendbridgemsg(const bridge_message_t &message);

   private:
    void onbridgemsg(const bridge_message_t &message);
    using onbridgemsg_action = action_wrapper<"onbridgemsg"_n, &stub_evm_runtime::onbridgemsg>;
};

void stub_evm_runtime::call(eosio::name from, const bytes& to, uint128_t value, const bytes& data, uint64_t gas_limit) {
}

void stub_evm_runtime::sendbridgemsg(const bridge_message_t &message) {
    onbridgemsg_action onbridgemsg_act(eosio::name("eosio.erc2o"), {{get_self(), "active"_n}});
    onbridgemsg_act.send(message);
}

}  // namespace stub