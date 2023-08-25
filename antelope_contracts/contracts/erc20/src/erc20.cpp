#include <erc20/bytecode.hpp>
#include <erc20/proxy_bytecode.hpp>
#include <erc20/eosio.token.hpp>
#include <erc20/erc20.hpp>
#include <erc20/hex.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/common/util.hpp>

namespace erc20 {

void erc20::init(uint64_t nonce) {
    require_auth(get_self());
    auto reserved_addr = silkworm::make_reserved_address(get_self().value);
    auto call_data = from_hex(bytecode);
    eosio::check(!!call_data, "bytecode should not be void");
    bytes to = {};
    bytes value_zero; 
    value_zero.resize(32, 0);

    // required account opened in evm_runtime
    call_action call_act(evm_account, {{get_self(), "active"_n}});
    call_act.send(get_self(), to, value_zero, *call_data, evm_init_gaslimit);

    evmc::address impl_addr = silkworm::create_address(reserved_addr, nonce); 

    impl_contract_table_t contract_table(_self, _self.value);
    contract_table.emplace(_self, [&](auto &v) {
        v.id = contract_table.available_primary_key();
        v.address.resize(kAddressLength);
        memcpy(&(v.address[0]), impl_addr.bytes, kAddressLength);
    });
}

[[eosio::action]] void erc20::regtoken(uint64_t nonce, eosio::name eos_contract_name, const eosio::asset& min_deposit, const eosio::asset& deposit_fee, std::string erc20_impl_address, int erc20_precision) {
    require_auth(get_self());

    std::optional<bytes> impl_address_bytes = from_hex(erc20_impl_address);
    eosio::check(!!impl_address_bytes && impl_address_bytes->size() == kAddressLength, "invalid erc20 address");  

    impl_contract_table_t contract_table(_self, _self.value);
    auto index = contract_table.get_index<"by.address"_n>();
    auto itr = index.find(make_key(*impl_address_bytes));

    eosio::check(itr != index.end(), "implementation contract must be deployed via erc20::init()");

    auto reserved_addr = silkworm::make_reserved_address(get_self().value);
    auto call_data = from_hex(proxy_bytecode);

    eosio::check(!!call_data, "proxy_bytecode should not be void");

    // constructor(address erc20_impl_contract)
    call_data->insert(call_data->end(), 32 - kAddressLength, 0);  // padding for address
    call_data->insert(call_data->end(), impl_address_bytes->begin(), impl_address_bytes->end());

    bytes to = {};
    bytes value_zero; 
    value_zero.resize(32, 0);

     // required account opened in evm_runtime
    call_action call_act(evm_account, {{get_self(), "active"_n}});
    call_act.send(get_self(), to, value_zero, *call_data, evm_init_gaslimit);

    evmc::address proxy_contract_addr = silkworm::create_address(reserved_addr, nonce); 

    token_table_t table(_self, _self.value);
    table.emplace(_self, [&](auto &v) {
        v.eos_contract_name = eos_contract_name;
        v.address.resize(kAddressLength, 0);
        memcpy(&(v.address[0]), proxy_contract_addr.bytes, kAddressLength);
        v.min_deposit = min_deposit;
        v.deposit_fee = deposit_fee;
        v.erc20_precision = erc20_precision;
    });
}

void erc20::onbridgemsg(const bridge_message_t &message) {

    check(get_sender() == evm_account, "invalid sender of onbridgemsg");

    const bridge_message_v0 &msg = std::get<bridge_message_v0>(message);
    check(msg.receiver == _self, "invalid message receiver");

    checksum256 addr_key = make_key(msg.sender);

    token_table_t token_table(_self, _self.value);
    auto index = token_table.get_index<"by.address"_n>();
    auto itr = index.find(addr_key);

    check(itr != index.end() && itr->address == msg.sender, "ERC-20 token not registerred");

    check(msg.data.size() >= 4, "not enough data in bridge_message_v0");
    if (*(uint32_t *)&(msg.data[0]) == 0xe5323365 /* big-endian 0x653332e5 */) {
        //sha("bridgeTransferV0(address,uint,string)") = 0xe5323365
        check(msg.data.size() >= 4 + kAddressLength + 32, "not enough data in bridge_message_v0 of application type 0xe5323365");

        evmc::address dest_addr;
        memcpy(dest_addr.bytes, (void *)&(msg.data[4]), kAddressLength);
        std::optional<uint64_t> dest_acc = silkworm::extract_reserved_address(dest_addr);
        check(!!dest_acc, "destination address in bridge_message_v0 must be reserved address");

        uint8_t amount_bytes[32]={};
        memcpy(amount_bytes, (void *)&(msg.data[4 + kAddressLength]), 32);
        
        intx::uint256 value{}, zero{0_u256};
        value = intx::be::load<intx::uint256>(amount_bytes);

        for (int i = itr->erc20_precision - itr->min_deposit.symbol.precision(); i > 0; --i) {
            check(value % 10 == zero, "bridge amount can not have dust");
            value /= 10;
        }

        uint64_t dest_amount = (uint64_t)value;
        check(intx::uint256(dest_amount) == value && dest_amount < (1ull<<62)-1, "bridge amount value overflow");
        check(dest_amount > 0, "bridge amount must be positive");

        std::string memo;
        int memo_len = (int)msg.data.size() - (4 + kAddressLength + 32);
        if (memo_len > 0) {
            memo.assign((const char *)&(msg.data[4 + kAddressLength + 32]), memo_len);
        }

        eosio::token::transfer_action transfer_act(itr->eos_contract_name, {{get_self(), "active"_n}});
        transfer_act.send(get_self(), eosio::name(*dest_acc), eosio::asset(dest_amount, itr->min_deposit.symbol), memo);
    } else {
        check(false, "unsupported bridge_message version");
    }
}

void erc20::transfer(eosio::name from, eosio::name to, eosio::asset quantity,
                     std::string memo) {

    if (to != get_self() || from == get_self()) return;

    uint128_t v = get_first_receiver().value;
    v <<= 64;
    v |= quantity.symbol.code().raw();

    token_table_t token_table(_self, _self.value);
    auto index = token_table.get_index<"by.symbol"_n>();
    auto itr = index.find(v);

    eosio::check(itr != index.end() && itr->min_deposit.symbol == quantity.symbol, "received unregistered token");
    eosio::check(quantity.amount >= itr->min_deposit.amount && quantity.amount > itr->deposit_fee.amount, "deposit amount too less");

    quantity.amount -= itr->deposit_fee.amount;
    eosio::check(quantity.amount > 0 && quantity.amount < (1ll<<62)-1, "deposit amount overflow");

    if (memo.size() == 42 && memo[0] == '0' && memo[1] == 'x')
        handle_erc20_transfer(*itr, quantity, memo);
    else
        eosio::check(false, "memo must be 0x EVM address");
}

void erc20::handle_erc20_transfer(const token_t &token, eosio::asset quantity, const std::string& memo) {
    const char method[4] = {'\xa9', '\x05', '\x9c', '\xbb'};  // sha3(transfer(address,uint256))[:4]

    auto address_bytes = from_hex(memo);
    eosio::check(!!address_bytes, "memo must be valid 0x EVM address");
    eosio::check(address_bytes->size() == kAddressLength, "memo must be valid 0x EVM address");

    intx::uint256 value((uint64_t)quantity.amount);

    for (int i = token.erc20_precision - quantity.symbol.precision(); i > 0; --i) {
        value *= 10;
    }

    uint8_t value_buffer[32] = {};
    intx::be::store(value_buffer, value);

    bytes call_data;
    call_data.reserve(4 + 64);
    call_data.insert(call_data.end(), method, method + 4);
    call_data.insert(call_data.end(), 32 - kAddressLength, 0);  // padding for address
    call_data.insert(call_data.end(), address_bytes->begin(), address_bytes->end());
    call_data.insert(call_data.end(), value_buffer, value_buffer + 32);

    call_action call_act(evm_account, {{get_self(), "active"_n}});

    bytes value_zero; // value of EVM native token (aka EOS)
    value_zero.resize(32, 0);

    call_act.send(get_self() /*from*/, token.address /*to*/, value_zero /*value*/, call_data /*data*/, evm_gaslimit /*gas_limit*/);
}

}  // namespace erc20