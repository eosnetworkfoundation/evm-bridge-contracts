#include <variant>
#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

using namespace eosio;

namespace stub {

typedef std::vector<char> bytes;
constexpr eosio::symbol token_symbol("EOS", 4u);

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
   [[eosio::action]] void init();
    [[eosio::action]] void call(eosio::name from, const bytes& to, uint128_t value, const bytes& data, uint64_t gas_limit);
    [[eosio::action]] void sendbridgemsg(const bridge_message_t &message);

    struct [[eosio::table]] [[eosio::contract("stub_evm_runtime")]] message_receiver {

    enum flag : uint32_t {
        FORCE_ATOMIC = 0x1
    };

    eosio::name     account;
    eosio::name     handler;
    eosio::asset    min_fee;
    uint32_t flags;

    uint64_t primary_key() const { return account.value; }
    bool has_flag(flag f) const {
        return (flags & f) != 0;
    }

    EOSLIB_SERIALIZE(message_receiver, (account)(handler)(min_fee)(flags));
};

typedef eosio::multi_index<"msgreceiver"_n, message_receiver> message_receiver_table;

   private:
    void onbridgemsg(const bridge_message_t &message);
    using onbridgemsg_action = action_wrapper<"onbridgemsg"_n, &stub_evm_runtime::onbridgemsg>;
};

void stub_evm_runtime::init() {
     auto update_row = [&](auto& row) {
        row.account = eosio::name("eosio.erc2o");
        row.handler = eosio::name("eosio.evmtok");
        row.min_fee = eosio::asset(100,token_symbol);
        row.flags   = message_receiver::FORCE_ATOMIC;
    };

    message_receiver_table message_receivers(get_self(), get_self().value);
    auto it = message_receivers.find(eosio::name("eosio.erc2o").value);

    if(it == message_receivers.end()) {
        message_receivers.emplace(get_self(), update_row);
    } else {
        message_receivers.modify(*it, eosio::same_payer, update_row);
    }
}

void stub_evm_runtime::call(eosio::name from, const bytes& to, uint128_t value, const bytes& data, uint64_t gas_limit) {
    require_auth(from);
}

void stub_evm_runtime::sendbridgemsg(const bridge_message_t &message) {
    onbridgemsg_action onbridgemsg_act(eosio::name("eosio.evmtok"), {{get_self(), "active"_n}});
    onbridgemsg_act.send(message);
}

}  // namespace stub