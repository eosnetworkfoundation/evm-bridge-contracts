#pragma once

#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>

using namespace eosio;

// Declaration of required actions and tables in evm_runtime
namespace evm_runtime {
    typedef std::vector<char> bytes;

    struct nextnonce {
        name     owner;
        uint64_t next_nonce = 0;

        uint64_t primary_key() const { return owner.value; }
        EOSLIB_SERIALIZE(nextnonce, (owner)(next_nonce));
    };

    typedef eosio::multi_index<"nextnonces"_n, evm_runtime::nextnonce> next_nonce_table;

    struct  message_receiver {
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

    class contract_actions {
        public:
        void call(eosio::name from, const bytes &to, const bytes& value, const bytes &data, uint64_t gas_limit);
        void assertnonce(eosio::name account, uint64_t next_nonce);
    };

    using call_action = action_wrapper<"call"_n, &contract_actions::call>;
    using assertnonce_action = action_wrapper<"assertnonce"_n, &contract_actions::assertnonce>;

} // evm_runtime
