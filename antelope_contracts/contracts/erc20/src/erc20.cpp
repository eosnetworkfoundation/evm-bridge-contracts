#include <erc20/bytecode.hpp>
#include <erc20/proxy_bytecode.hpp>
#include <erc20/eosio.token.hpp>
#include <erc20/erc20.hpp>
#include <erc20/hex.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/common/util.hpp>

namespace eosio {
   namespace internal_use_do_not_use {
      extern "C" {
         __attribute__((eosio_wasm_import))
         uint32_t get_code_hash(uint64_t account, uint32_t struct_version, char* data, uint32_t size);
      }
   }
}

namespace erc20 {

checksum256 get_code_hash(name account) {
    char buff[64];

    eosio::check(internal_use_do_not_use::get_code_hash(account.value, 0, buff, sizeof(buff)) <= sizeof(buff), "get_code_hash() too big");
    using start_of_code_hash_return = std::tuple<unsigned_int, uint64_t, checksum256>;
    const auto& [v, s, code_hash] = unpack<start_of_code_hash_return>(buff, sizeof(buff));

    return code_hash;
}

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

[[eosio::action]] void erc20::regtoken(uint64_t nonce, eosio::name eos_contract_name, std::string evm_token_name, std::string evm_token_symbol, const eosio::asset& min_deposit, const eosio::asset& deposit_fee, std::string erc20_impl_address, int erc20_precision) {
    require_auth(get_self());

    eosio::check(evm_token_name.length() > 0 && evm_token_name.length() < 32, "invalid evm_token_name");
    eosio::check(evm_token_symbol.length() > 0 && evm_token_symbol.length() < 32, "invalid evm_token_symbol");

    std::optional<bytes> impl_address_bytes = from_hex(erc20_impl_address);
    eosio::check(!!impl_address_bytes && impl_address_bytes->size() == kAddressLength, "invalid erc20 address");

    uint128_t v = eos_contract_name.value;
    v <<= 64;
    v |= min_deposit.symbol.code().raw();
    token_table_t token_table(_self, _self.value);
    auto index_symbol = token_table.get_index<"by.symbol"_n>();
    check(index_symbol.find(v) == index_symbol.end(), "token already registered");

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

    bytes constructor_data;
    // sha(initialize(uint8 _precision,string memory _name,string memory _symbol,string memory _eos_token_contract)) == 0x0735df57
    uint8_t func_[4] = {0x07,0x35,0xdf,0x57};
    constructor_data.insert(constructor_data.end(), func_, func_ + sizeof(func_));
    
    auto pack_uint32 = [&](bytes &ds, uint32_t val) {
        uint8_t val_[32] = {};
        val_[28] = (uint8_t)(val >> 24);
        val_[29] = (uint8_t)(val >> 16);
        val_[30] = (uint8_t)(val >> 8);
        val_[31] = (uint8_t)val;
        ds.insert(ds.end(), val_, val_ + sizeof(val_));
    };
    auto pack_string = [&](bytes &ds, const auto &str) {
        pack_uint32(ds, (uint32_t)str.size());
        for (size_t i = 0; i < (str.size() + 31) / 32 * 32; i += 32) {
            uint8_t name_[32] = {};
            memcpy(name_, str.data() + i, i + 32 > str.size() ? str.size() - i : 32);
            ds.insert(ds.end(), name_, name_ + sizeof(name_));
        }
    };

    pack_uint32(constructor_data, (uint8_t)erc20_precision); // offset 0
    pack_uint32(constructor_data, 128);                      // offset 32
    pack_uint32(constructor_data, 192);                      // offset 64
    pack_uint32(constructor_data, 256);                      // offset 96
    pack_string(constructor_data, evm_token_name);           // offset 128
    pack_string(constructor_data, evm_token_symbol);         // offset 192
    pack_string(constructor_data, eos_contract_name.to_string()); // offset 256

    pack_uint32(*call_data, 64);
    pack_string(*call_data, constructor_data);

    bytes to = {};
    bytes value_zero; 
    value_zero.resize(32, 0);

     // required account opened in evm_runtime
    call_action call_act(evm_account, {{get_self(), "active"_n}});
    call_act.send(get_self(), to, value_zero, *call_data, evm_init_gaslimit);

    evmc::address proxy_contract_addr = silkworm::create_address(reserved_addr, nonce); 

    token_table.emplace(_self, [&](auto &v) {
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

        eosio::name dest_eos_acct(*dest_acc);
        if (get_code_hash(dest_eos_acct) != checksum256()) {
            egresslist_table_t(get_self(), get_self().value).get(dest_eos_acct.value, "native accounts containing contract code must be on allow list for egress bridging");
        }

        eosio::token::transfer_action transfer_act(itr->eos_contract_name, {{get_self(), "active"_n}});
        transfer_act.send(get_self(), dest_eos_acct, eosio::asset(dest_amount, itr->min_deposit.symbol), memo);

        token_table.modify(*itr, _self, [&](auto &v) {
            v.balance -= dest_amount;
        });
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

    if (memo.size() == 42 && memo[0] == '0' && memo[1] == 'x') {
        handle_erc20_transfer(*itr, quantity, memo);
        token_table.modify(*itr, _self, [&](auto &v) {
            v.balance += quantity.amount;
        });
    } else
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

void erc20::addegress(const std::vector<name>& accounts) {
    require_auth(get_self());

    egresslist_table_t egresslist_table(get_self(), get_self().value);

    for(const name& account : accounts)
        if(egresslist_table.find(account.value) == egresslist_table.end())
            egresslist_table.emplace(get_self(), [&](allowed_egress_account& a) {
                a.account = account;
            });
}

void erc20::removeegress(const std::vector<name>& accounts) {
    require_auth(get_self());

    egresslist_table_t egresslist_table(get_self(), get_self().value);

    for(const name& account : accounts)
        if(auto it = egresslist_table.find(account.value); it != egresslist_table.end())
            egresslist_table.erase(it);
}

}  // namespace erc20