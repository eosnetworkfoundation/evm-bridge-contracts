#include <erc20/eosio.token.hpp>
#include <erc20/erc20.hpp>
#include <erc20/hex.hpp>
#include <erc20/evm_runtime.hpp>

#include <erc20/bytecode.hpp>
#include <erc20/proxy_bytecode.hpp>

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

inline uint128_t token_symbol_key(eosio::name token_contract, eosio::symbol_code symbol_code) {
    uint128_t v = token_contract.value;
    v <<= 64;
    v |= symbol_code.raw();
    return v;
}

template <size_t Size>
void initialize_data(bytes& output, const unsigned char (&arr)[Size]) {
    static_assert(Size > 128); // ensure bytecode is compiled
    output.resize(Size);
    std::memcpy(output.data(), arr, Size);
}

// lookup nonce from the multi_index table of evm contract and assert
uint64_t erc20::get_next_nonce() { 

    config_t config = get_config();

    evm_runtime::next_nonce_table table(config.evm_account, config.evm_account.value);
    auto itr = table.find(receiver_account().value);
    uint64_t next_nonce = (itr == table.end() ? 0 : itr->next_nonce);

    evm_runtime::assertnonce_action act(config.evm_account, std::vector<eosio::permission_level>{});
    act.send(receiver_account(), next_nonce);
    return next_nonce;
}

void erc20::upgrade() {
    require_auth(get_self());

    uint64_t id = 0;
    impl_contract_table_t contract_table(_self, _self.value);
    check(contract_table.find(id) == contract_table.end(), "implementation contract already deployed");

    bytes call_data;

    auto reserved_addr = silkworm::make_reserved_address(receiver_account().value);
    initialize_data(call_data, solidity::erc20::bytecode);

    bytes to = {};
    bytes value_zero; 
    value_zero.resize(32, 0);

    uint64_t next_nonce = get_next_nonce();

    // required account opened in evm_runtime
    config_t config = get_config();
    evm_runtime::call_action call_act(config.evm_account, {{receiver_account(), "active"_n}});
    call_act.send(receiver_account(), to, value_zero, call_data, config.evm_init_gaslimit);

    evmc::address impl_addr = silkworm::create_address(reserved_addr, next_nonce); 

    contract_table.emplace(_self, [&](auto &v) {
        v.id = contract_table.available_primary_key();
        v.address.resize(kAddressLength);
        memcpy(&(v.address[0]), impl_addr.bytes, kAddressLength);
    });
}

void erc20::upgradeto(std::string impl_address) {
    require_auth(get_self());
    auto address_bytes = from_hex(impl_address);
    eosio::check(!!address_bytes, "implementation address must be valid 0x EVM address");
    eosio::check(address_bytes->size() == kAddressLength, "invalid length of implementation address");

    uint64_t id = 0;
    impl_contract_table_t contract_table(_self, _self.value);

    contract_table.emplace(_self, [&](auto &v) {
        v.id = contract_table.available_primary_key();
        v.address.resize(kAddressLength);
        memcpy(&(v.address[0]), address_bytes->data(), kAddressLength);
    });
}

[[eosio::action]] void erc20::regtoken(eosio::name token_contract, std::string evm_token_name, std::string evm_token_symbol, const eosio::asset& ingress_fee, const eosio::asset &egress_fee, uint8_t erc20_precision) {
    require_auth(get_self());
    config_t config = get_config();

    eosio::check(eosio::is_account(token_contract), "invalid token_contract");
    
    // keep the name & symbol fit into 32 byte, which is the alignment in EVM
    eosio::check(evm_token_name.length() > 0 && evm_token_name.length() < 32, "invalid evm_token_name length");
    eosio::check(evm_token_symbol.length() > 0 && evm_token_symbol.length() < 32, "invalid evm_token_symbol length");

    // 2^(256-64) = 6.2e+57, so the precision diff is at most 57
    eosio::check(erc20_precision >= ingress_fee.symbol.precision() &&
    erc20_precision <= ingress_fee.symbol.precision() + 57, "erc20 precision out of range");

    eosio::check(egress_fee.symbol == config.evm_gas_token_symbol, "egress_fee should have native token symbol");
    intx::uint256 egress_fee_evm = egress_fee.amount;
    egress_fee_evm *= get_minimum_natively_representable(config);

    token_table_t token_table(_self, _self.value);
    auto index_symbol = token_table.get_index<"by.symbol"_n>();
    check(index_symbol.find(token_symbol_key(token_contract, ingress_fee.symbol.code())) == index_symbol.end(), "token already registered");

    impl_contract_table_t contract_table(_self, _self.value);
    eosio::check(contract_table.begin() != contract_table.end(), "no implementaion contract available");
    auto contract_itr = contract_table.end();
    --contract_itr;

    auto reserved_addr = silkworm::make_reserved_address(receiver_account().value);

    bytes call_data;
    initialize_data(call_data, solidity::proxy::bytecode);

    // constructor(address erc20_impl_contract, memory _data)
    call_data.insert(call_data.end(), 32 - kAddressLength, 0);  // padding for address
    call_data.insert(call_data.end(), contract_itr->address.begin(), contract_itr->address.end());

    bytes constructor_data;
    // sha(function initialize(uint8 _precision,uint256 _egressFee,string memory _name,string memory _symbol,string memory _eos_token_contract)) == 0xd66d4ac3
    uint8_t func_[4] = {0xd6,0x6d,0x4a,0xc3};
    constructor_data.insert(constructor_data.end(), func_, func_ + sizeof(func_));

    auto pack_uint256 = [&](bytes &ds, const intx::uint256 &val) {
        uint8_t val_[32] = {};
        intx::be::store(val_, val);
        ds.insert(ds.end(), val_, val_ + sizeof(val_));
    };
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
    pack_uint256(constructor_data, egress_fee_evm);          // offset 32
    pack_uint32(constructor_data, 160);                      // offset 64
    pack_uint32(constructor_data, 224);                      // offset 96
    pack_uint32(constructor_data, 288);                      // offset 128
    pack_string(constructor_data, evm_token_name);           // offset 160
    pack_string(constructor_data, evm_token_symbol);         // offset 224
    pack_string(constructor_data, token_contract.to_string()); // offset 288

    pack_uint32(call_data, 64);                  // offset 32
    pack_string(call_data, constructor_data);    // offset 64

    bytes to = {};
    bytes value_zero; 
    value_zero.resize(32, 0);

    uint64_t next_nonce = get_next_nonce();

    // required account opened in evm_runtime
    evm_runtime::call_action call_act(config.evm_account, {{receiver_account(), "active"_n}});
    call_act.send(receiver_account(), to, value_zero, call_data, config.evm_init_gaslimit);

    evmc::address proxy_contract_addr = silkworm::create_address(reserved_addr, next_nonce); 

    token_table.emplace(_self, [&](auto &v) {
        v.id = token_table.available_primary_key();
        v.token_contract = token_contract;
        v.address.resize(kAddressLength, 0);
        memcpy(&(v.address[0]), proxy_contract_addr.bytes, kAddressLength);
        v.ingress_fee = ingress_fee;
        v.balance = ingress_fee;
        v.balance.amount = 0;
        v.fee_balance = v.balance;
        v.erc20_precision = erc20_precision;
    });
}

void erc20::onbridgemsg(const bridge_message_t &message) {

    config_t config = get_config();

    check(get_sender() == config.evm_account, "invalid sender of onbridgemsg");

    const bridge_message_v0 &msg = std::get<bridge_message_v0>(message);
    check(msg.receiver == receiver_account(), "invalid message receiver");

    checksum256 addr_key = make_key(msg.sender);

    token_table_t token_table(_self, _self.value);
    auto index = token_table.get_index<"by.address"_n>();
    auto itr = index.find(addr_key);

    check(itr != index.end() && itr->address == msg.sender, "ERC-20 token not registerred");

    check(msg.data.size() >= 4, "not enough data in bridge_message_v0");

    uint32_t app_type = 0;
    memcpy((void *)&app_type, (const void *)&(msg.data[0]), sizeof(app_type));

    if (app_type == 0xe5323365 /* big-endian 0x653332e5 */) {
        // abi.encodeWithSignature("bridgeTransferV0(address,uint,string)", to, amount, memo);
        // sha("bridgeTransferV0(address,uint,string)") = 0x653332e5
        check(msg.data.size() >= 4 + 32 /*to*/ + 32 /*amount*/ + 32 /*memo offset*/ + 32 /*memo len*/, 
            "not enough data in bridge_message_v0 of application type 0x653332e5");

        auto read_uint256 = [&](const auto &msg, size_t offset) -> intx::uint256 {
            uint8_t buffer[32]={};
            check(msg.data.size() >= offset + 32, "not enough data in bridge_message_v0 of application type 0x653332e5");
            memcpy(buffer, (void *)&(msg.data[offset]), 32);
            return intx::be::load<intx::uint256>(buffer);
        };

        check(read_uint256(msg, 4) <= 0xffffFFFFffffFFFFffffFFFFffffFFFFffffFFFF_u256, "invalid destination address");
        evmc::address dest_addr;
        memcpy(dest_addr.bytes, (void *)&(msg.data[4 + 32 - kAddressLength]), kAddressLength);
        std::optional<uint64_t> dest_acc = silkworm::extract_reserved_address(dest_addr);
        check(!!dest_acc, "destination address in bridge_message_v0 must be reserved address");

        intx::uint256 value = read_uint256(msg, 4 + 32);
        intx::uint256 mult = intx::exp(10_u256, intx::uint256(itr->erc20_precision - itr->ingress_fee.symbol.precision()));
        check(value % mult == 0_u256, "bridge amount can not have dust");
        value /= mult;

        uint64_t dest_amount = (uint64_t)value;
        check(intx::uint256(dest_amount) == value && dest_amount < (1ull<<62)-1, "bridge amount value overflow");
        check(dest_amount > 0, "bridge amount must be positive");

        check(read_uint256(msg, 4 + 32 + 32) == 96_u256, "invalid memo offset in bridge_message_v0");

        intx::uint256 memo_len_ = read_uint256(msg, 4 + 32 + 32 + 32);
        size_t memo_len = (uint64_t)(memo_len_);
        check(memo_len_ <= 256_u256 && msg.data.size() >= 4 + 32 + 32 + 32 + 32 + memo_len, 
            "invalid memo length in bridge_message_v0");
        std::string memo;
        if (memo_len > 0) {
            memo.assign((const char *)&(msg.data[4 + 32 + 32 + 32 + 32]), memo_len);
        }

        eosio::name dest_eos_acct(*dest_acc);
        if (::erc20::get_code_hash(dest_eos_acct) != checksum256()) {
            egresslist_table_t(get_self(), get_self().value).get(dest_eos_acct.value, "native accounts containing contract code must be on allow list for egress bridging");
        }

        eosio::token::transfer_action transfer_act(itr->token_contract, {{get_self(), "active"_n}});
        transfer_act.send(get_self(), dest_eos_acct, eosio::asset(dest_amount, itr->ingress_fee.symbol), memo);

        token_table.modify(*itr, _self, [&](auto &v) {
            v.balance.amount -= dest_amount;
        });
    } else {
        eosio::check(false, "unsupported bridge_message version");
    }
}

void erc20::transfer(eosio::name from, eosio::name to, eosio::asset quantity,
                     std::string memo) {

    if (to != get_self() || from == get_self()) return;

    token_table_t token_table(_self, _self.value);
    auto index = token_table.get_index<"by.symbol"_n>();
    auto itr = index.find(token_symbol_key(get_first_receiver(), quantity.symbol.code()));

    eosio::check(itr != index.end() && itr->ingress_fee.symbol == quantity.symbol, "received unregistered token");
    eosio::check(quantity.amount > itr->ingress_fee.amount, "deposit amount must be greater than ingress fee");

    quantity -= itr->ingress_fee;
    eosio::check(quantity.amount > 0 && quantity.amount < (1ll<<62)-1, "deposit amount overflow");

    if (memo.size() == 42 && memo[0] == '0' && memo[1] == 'x') {
        handle_erc20_transfer(*itr, quantity, memo);
        token_table.modify(*itr, _self, [&](auto &v) {
            v.balance += quantity;
            v.fee_balance += v.ingress_fee; 
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
    value *= intx::exp(10_u256, intx::uint256(token.erc20_precision - quantity.symbol.precision()));

    uint8_t value_buffer[32] = {};
    intx::be::store(value_buffer, value);

    bytes call_data;
    call_data.reserve(4 + 64);
    call_data.insert(call_data.end(), method, method + 4);
    call_data.insert(call_data.end(), 32 - kAddressLength, 0);  // padding for address
    call_data.insert(call_data.end(), address_bytes->begin(), address_bytes->end());
    call_data.insert(call_data.end(), value_buffer, value_buffer + 32);

    config_t config = get_config();
    evm_runtime::call_action call_act(config.evm_account, {{receiver_account(), "active"_n}});

    bytes value_zero; // value of EVM native token (aka EOS)
    value_zero.resize(32, 0);

    call_act.send(receiver_account() /*from*/, token.address /*to*/, value_zero /*value*/, call_data /*data*/, config.evm_gaslimit /*gas_limit*/);
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

void erc20::withdrawfee(eosio::name token_contract, eosio::asset quantity, eosio::name to, std::string memo) {
    require_auth(get_self());

    token_table_t token_table(_self, _self.value);
    auto index = token_table.get_index<"by.symbol"_n>();
    auto itr = index.find(token_symbol_key(token_contract, quantity.symbol.code()));

    eosio::check(itr != index.end(), "token not registered");
    eosio::check(itr->fee_balance.symbol == quantity.symbol, "incorrect precision for registered token");
    eosio::check(quantity.amount > 0, "quantity must be positive");
    eosio::check(itr->fee_balance >= quantity, "overdrawn balance");
    token_table.modify(*itr, _self, [&](auto &v) {
        v.fee_balance -= quantity;
    });

    eosio::token::transfer_action transfer_act(itr->token_contract, {{get_self(), "active"_n}});
    transfer_act.send(get_self(), to, quantity, memo);
}

void erc20::setingressfee(eosio::name token_contract, eosio::asset ingress_fee) {
    require_auth(get_self());

    token_table_t token_table(_self, _self.value);
    auto index = token_table.get_index<"by.symbol"_n>();
    auto itr = index.find(token_symbol_key(token_contract, ingress_fee.symbol.code()));

    eosio::check(itr != index.end(), "token not registered");
    eosio::check(itr->ingress_fee.symbol == ingress_fee.symbol, "incorrect precision for registered token");
    eosio::check(ingress_fee.amount >= 0, "ingress fee can not be negative");

    token_table.modify(*itr, _self, [&](auto &v) {
        v.ingress_fee = ingress_fee;
    });
}

void erc20::setegressfee(eosio::name token_contract, eosio::symbol_code token_symbol_code, const eosio::asset &egress_fee) {
    require_auth(get_self());

    config_t config = get_config();

    eosio::check(egress_fee.symbol == config.evm_gas_token_symbol, "egress_fee should have native token symbol");

    token_table_t token_table(_self, _self.value);
    auto index_symbol = token_table.get_index<"by.symbol"_n>();
    auto token_table_iter = index_symbol.find(token_symbol_key(token_contract, token_symbol_code));
    eosio::check(token_table_iter != index_symbol.end(), "token not registered");

    
    evm_runtime::message_receiver_table message_receivers(config.evm_account, config.evm_account.value);
    auto message_receivers_iter = message_receivers.find(receiver_account().value);
    eosio::check(message_receivers_iter != message_receivers.end(), "receiver not registered in evm contract");
    
    eosio::check(egress_fee >= message_receivers_iter->min_fee, "egress fee must be at least as large as the receiver's minimum fee");
    
    intx::uint256 egress_fee_evm = egress_fee.amount;
    egress_fee_evm *= get_minimum_natively_representable(config);

    auto pack_uint256 = [&](bytes &ds, const intx::uint256 &val) {
        uint8_t val_[32] = {};
        intx::be::store(val_, val);
        ds.insert(ds.end(), val_, val_ + sizeof(val_));
    };

    bytes call_data;
    // sha(setFee(uint256)) == 0x69fe0e2d
    uint8_t func_[4] = {0x69,0xfe,0x0e,0x2d};
    call_data.insert(call_data.end(), func_, func_ + sizeof(func_));
    pack_uint256(call_data, egress_fee_evm);

    bytes value_zero; 
    value_zero.resize(32, 0);

    evm_runtime::call_action call_act(config.evm_account, {{receiver_account(), "active"_n}});
    call_act.send(receiver_account(), token_table_iter->address, value_zero, call_data, config.evm_gaslimit);
}

void erc20::unregtoken(eosio::name token_contract, eosio::symbol_code token_symbol_code) {
    require_auth(get_self());

    token_table_t token_table(_self, _self.value);
    auto index_symbol = token_table.get_index<"by.symbol"_n>();
    auto token_table_iter = index_symbol.find(token_symbol_key(token_contract, token_symbol_code));
    eosio::check(token_table_iter != index_symbol.end(), "token not registered");

    index_symbol.erase(token_table_iter);
}

void erc20::init(eosio::name evm_account, eosio::symbol gas_token_symbol, uint64_t gaslimit, uint64_t init_gaslimit) {
    require_auth(get_self());

    config_singleton_t config_table(get_self(), get_self().value);
    eosio::check(!config_table.exists(), "erc20 config already initialized");

    config_t config;
    token_table_t token_table(_self, _self.value);
    if (token_table.begin() != token_table.end()) {
        eosio::check(evm_account == default_evm_account && gas_token_symbol == default_native_token_symbol, "can only init with native EOS symbol");
    }
    config.evm_account = evm_account;
    config.evm_gas_token_symbol = gas_token_symbol;
    config.evm_gaslimit = gaslimit;
    config.evm_init_gaslimit = init_gaslimit;
    set_config(config);
}

void erc20::setgaslimit(std::optional<uint64_t> gaslimit, std::optional<uint64_t> init_gaslimit) {
    require_auth(get_self());

    config_t config = get_config();
    if (gaslimit.has_value()) config.evm_gaslimit = *gaslimit;
    if (init_gaslimit.has_value()) config.evm_init_gaslimit = *init_gaslimit;
    set_config(config);
}

inline eosio::name erc20::receiver_account()const {
    return get_self();
}

void erc20::callupgaddr(std::string proxy_address){
    require_auth(get_self());

    auto address_bytes = from_hex(proxy_address);
    eosio::check(!!address_bytes, "token address must be valid 0x EVM address");
    eosio::check(address_bytes->size() == kAddressLength, "invalid length of token address");

    checksum256 addr_key = make_key(*address_bytes);
    token_table_t token_table(_self, _self.value);
    auto index = token_table.get_index<"by.address"_n>();
    auto token_table_iter = index.find(addr_key);

    check(token_table_iter != index.end() && token_table_iter->address == address_bytes, "ERC-20 token not registerred");

    handle_call_upgrade(token_table_iter->address);
}

void erc20::callupgsym(eosio::name token_contract, eosio::symbol token_symbol){
    require_auth(get_self());

    token_table_t token_table(_self, _self.value);
    auto index_symbol = token_table.get_index<"by.symbol"_n>();
    auto token_table_iter = index_symbol.find(token_symbol_key(token_contract, token_symbol.code()));
    eosio::check(token_table_iter != index_symbol.end(), "token not registered");
    
    handle_call_upgrade(token_table_iter->address);
}

void erc20::handle_call_upgrade(const bytes& proxy_address) {
    config_t config = get_config();
    impl_contract_table_t contract_table(_self, _self.value);
    eosio::check(contract_table.begin() != contract_table.end(), "no implementaion contract available");
    auto contract_itr = contract_table.end();
    --contract_itr;
 
    auto pack_uint32 = [&](bytes &ds, uint32_t val) {
        uint8_t val_[32] = {};
        val_[28] = (uint8_t)(val >> 24);
        val_[29] = (uint8_t)(val >> 16);
        val_[30] = (uint8_t)(val >> 8);
        val_[31] = (uint8_t)val;
        ds.insert(ds.end(), val_, val_ + sizeof(val_));
    };

    bytes call_data;
    // sha(upgradeTo(address)) == 3659cfe6
    uint8_t func_[4] = {0x36,0x59,0xcf,0xe6};
    call_data.insert(call_data.end(), func_, func_ + sizeof(func_));
    
    
    call_data.insert(call_data.end(), 32 - kAddressLength, 0);  // padding for address offset 0
    call_data.insert(call_data.end(), contract_itr->address.begin(), contract_itr->address.end()); 

    bytes value_zero; 
    value_zero.resize(32, 0);

    evm_runtime::call_action call_act(config.evm_account, {{receiver_account(), "active"_n}});
    call_act.send(receiver_account(), proxy_address, value_zero, call_data, config.evm_gaslimit);
}

}  // namespace erc20