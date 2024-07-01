#include <evmutil/eosio.token.hpp>
#include <evmutil/evmutil.hpp>
#include <evmutil/hex.hpp>
#include <evmutil/evm_runtime.hpp>
#include <evmutil/endrmng.hpp>

#include <evmutil/claim_reward_helper_bytecode.hpp>
#include <evmutil/stakehelper_bytecode.hpp>
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

namespace evmutil {

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
uint64_t evmutil::get_next_nonce() { 

    config_t config = get_config();

    evm_runtime::next_nonce_table table(config.evm_account, config.evm_account.value);
    auto itr = table.find(receiver_account().value);
    uint64_t next_nonce = (itr == table.end() ? 0 : itr->next_nonce);

    evm_runtime::assertnonce_action act(config.evm_account, std::vector<eosio::permission_level>{});
    act.send(receiver_account(), next_nonce);
    return next_nonce;
}

void evmutil::deployimpls() {
    require_auth(get_self());


    uint64_t id = 0;
    impl_contract_table_t contract_table(_self, _self.value);
    check(contract_table.find(id) == contract_table.end(), "implementation contract already deployed");

    bytes call_data;

    auto reserved_addr = silkworm::make_reserved_address(receiver_account().value);
    initialize_data(call_data, solidity::stakehelper::bytecode);

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
        v.id = id;
        v.address.resize(kAddressLength);
        memcpy(&(v.address[0]), impl_addr.bytes, kAddressLength);
    });

}

void evmutil::deployhelper() {
    require_auth(get_self());

    uint64_t id = 0;
    util_contract_table_t contract_table(_self, _self.value);
    check(contract_table.find(id) == contract_table.end(), "implementation contract already deployed");

    bytes call_data;

    auto reserved_addr = silkworm::make_reserved_address(receiver_account().value);
    initialize_data(call_data, solidity::claimrewardhelper::bytecode);

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
        v.id = id;
        v.address.resize(kAddressLength);
        memcpy(&(v.address[0]), impl_addr.bytes, kAddressLength);
    });


}

void evmutil::setutilimpl(std::string impl_address) {
    require_auth(get_self());
    auto address_bytes = from_hex(impl_address);
    eosio::check(!!address_bytes, "implementation address must be valid 0x EVM address");
    eosio::check(address_bytes->size() == kAddressLength, "invalid length of implementation address");

    uint64_t id = 0;
    util_contract_table_t contract_table(_self, _self.value);

    contract_table.emplace(_self, [&](auto &v) {
        v.id = id;
        v.address.resize(kAddressLength);
        memcpy(&(v.address[0]), address_bytes->data(), kAddressLength);
    });
}

void evmutil::setstakeimpl(std::string impl_address) {
    require_auth(get_self());
    auto address_bytes = from_hex(impl_address);
    eosio::check(!!address_bytes, "implementation address must be valid 0x EVM address");
    eosio::check(address_bytes->size() == kAddressLength, "invalid length of implementation address");

    uint64_t id = 0;
    impl_contract_table_t contract_table(_self, _self.value);

    contract_table.emplace(_self, [&](auto &v) {
        v.id = id;
        v.address.resize(kAddressLength);
        memcpy(&(v.address[0]), address_bytes->data(), kAddressLength);
    });
}

void evmutil::regtokenwithcodebytes(const bytes& erc20_address_bytes, const bytes& impl_address_bytes, const eosio::asset& dep_fee, uint8_t erc20_precision) {
    require_auth(get_self());
    
    eosio::check(impl_address_bytes.size() == kAddressLength, "invalid length of implementation address");

    config_t config = get_config();
    

    // 2^(256-64) = 6.2e+57, so the precision diff is at most 57
    eosio::check(erc20_precision >= dep_fee.symbol.precision() &&
    erc20_precision <= dep_fee.symbol.precision() + 57, "evmutil precision out of range");

    eosio::check(dep_fee.symbol == config.evm_gas_token_symbol, "egress_fee should have native token symbol");
    intx::uint256 dep_fee_evm = dep_fee.amount;
    dep_fee_evm *= get_minimum_natively_representable(config);

    token_table_t token_table(_self, _self.value);
    auto index_symbol = token_table.get_index<"by.tokenaddr"_n>();
    check(index_symbol.find(make_key(erc20_address_bytes)) == index_symbol.end(), "token already registered");

    auto reserved_addr = silkworm::make_reserved_address(receiver_account().value);

    bytes call_data;
    initialize_data(call_data, solidity::proxy::bytecode);

    // constructor(address evmutil_impl_contract, memory _data)
    call_data.insert(call_data.end(), 32 - kAddressLength, 0);  // padding for address
    call_data.insert(call_data.end(), impl_address_bytes.begin(), impl_address_bytes.end());

    bytes constructor_data;
    // initialize(address,uint256) => cd6dc687
    uint8_t func_[4] = {0xcd,0x6d,0xc6,0x87};
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
    
    constructor_data.insert(constructor_data.end(), 32 - kAddressLength, 0);  // padding for address
    constructor_data.insert(constructor_data.end(), erc20_address_bytes.begin(), erc20_address_bytes.end());

    pack_uint256(constructor_data, dep_fee_evm);          // offset 32

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
        v.address.resize(kAddressLength, 0);
        memcpy(&(v.address[0]), proxy_contract_addr.bytes, kAddressLength);
        v.erc20_precision = erc20_precision;
        v.token_address.resize(kAddressLength, 0);
        memcpy(&(v.token_address[0]), erc20_address_bytes.data(), kAddressLength);
    });
}

[[eosio::action]] void evmutil::regwithcode(std::string token_address, std::string impl_address, const eosio::asset &dep_fee, uint8_t erc20_precision) {
    require_auth(get_self());
    auto address_bytes = from_hex(impl_address);
    eosio::check(!!address_bytes, "implementation address must be valid 0x EVM address");
    eosio::check(address_bytes->size() == kAddressLength, "invalid length of implementation address");

    auto token_address_bytes = from_hex(token_address);
    eosio::check(!!token_address_bytes, "token address must be valid 0x EVM address");
    eosio::check(token_address_bytes->size() == kAddressLength, "invalid length of token address");

    regtokenwithcodebytes(*token_address_bytes, *address_bytes, dep_fee, erc20_precision);

}

[[eosio::action]] void evmutil::regtoken(std::string token_address, const eosio::asset &dep_fee, uint8_t erc20_precision) {
    require_auth(get_self());
    
    impl_contract_table_t contract_table(_self, _self.value);
    eosio::check(contract_table.begin() != contract_table.end(), "no implementaion contract available");
    auto contract_itr = contract_table.end();
    --contract_itr;

    auto token_address_bytes = from_hex(token_address);
    eosio::check(!!token_address_bytes, "token address must be valid 0x EVM address");
    eosio::check(token_address_bytes->size() == kAddressLength, "invalid length of token address");

    regtokenwithcodebytes(*token_address_bytes, contract_itr->address, dep_fee, erc20_precision);

}

void evmutil::handle_endorser_stakes(const bridge_message_v0 &msg, uint64_t delta_precision) {

    check(msg.data.size() >= 4, "not enough data in bridge_message_v0");
    config_t config = get_config();

    uint32_t app_type = 0;
    memcpy((void *)&app_type, (const void *)&(msg.data[0]), sizeof(app_type));
    // 0xdc4653f4 : f45346dc : deposit(address,uint256,address)
    // 0xec8d3269 : 69328dec : withdraw(address,uint256,address)
    // 0x42b3c021 : 21c0b342 : claim(address,address)

    auto read_uint256 = [&](const auto &msg, size_t offset) -> intx::uint256 {
            uint8_t buffer[32]={};
            check(msg.data.size() >= offset + 32, "not enough data in bridge_message_v0 of application type 0x42b3c021");
            memcpy(buffer, (void *)&(msg.data[offset]), 32);
            return intx::be::load<intx::uint256>(buffer);
    };

    if (app_type == 0x42b3c021) /* claim(address,address) */{
        check(msg.data.size() >= 4 + 32 /*to*/ + 32 /*from*/, 
            "not enough data in bridge_message_v0 of application type 0x653332e5");

        check(read_uint256(msg, 4) <= 0xffffFFFFffffFFFFffffFFFFffffFFFFffffFFFF_u256, "invalid destination address");
        evmc::address dest_addr;
        memcpy(dest_addr.bytes, (void *)&(msg.data[4 + 32 - kAddressLength]), kAddressLength);
        std::optional<uint64_t> dest_acc = silkworm::extract_reserved_address(dest_addr);
        check(!!dest_acc, "destination address in bridge_message_v0 must be reserved address");

        check(read_uint256(msg, 4 + 32) <= 0xffffFFFFffffFFFFffffFFFFffffFFFFffffFFFF_u256, "invalid sender address");
        evmc::address sender_addr;
        memcpy(sender_addr.bytes, (void *)&(msg.data[4 + 32 + 32 - kAddressLength]), kAddressLength);


        endrmng::evmclaim_action evmclaim_act(config.endrmng_account, {{receiver_account(), "active"_n}});
        evmclaim_act.send(make_key(msg.sender), make_key(sender_addr.bytes, kAddressLength), *dest_acc);

    
    } else if (app_type == 0xdc4653f4) /* deposit(address,uint256,address) */{
        check(read_uint256(msg, 4) <= 0xffffFFFFffffFFFFffffFFFFffffFFFFffffFFFF_u256, "invalid destination address");
        evmc::address dest_addr;
        memcpy(dest_addr.bytes, (void *)&(msg.data[4 + 32 - kAddressLength]), kAddressLength);
        std::optional<uint64_t> dest_acc = silkworm::extract_reserved_address(dest_addr);
        check(!!dest_acc, "destination address in bridge_message_v0 must be reserved address");

        intx::uint256 value = read_uint256(msg, 4 + 32);
        intx::uint256 mult = intx::exp(10_u256, intx::uint256(delta_precision));
        check(value % mult == 0_u256, "bridge amount can not have dust");
        value /= mult;

        uint64_t dest_amount = (uint64_t)value;
        check(intx::uint256(dest_amount) == value && dest_amount < (1ull<<62)-1, "bridge amount value overflow");
        check(dest_amount > 0, "bridge amount must be positive");

        check(read_uint256(msg, 4 + 32 + 32) <= 0xffffFFFFffffFFFFffffFFFFffffFFFFffffFFFF_u256, "invalid sender address");
        evmc::address sender_addr;
        memcpy(sender_addr.bytes, (void *)&(msg.data[4 + 32 + 32 + 32 - kAddressLength]), kAddressLength);

        endrmng::evmstake_action evmstake_act(config.endrmng_account, {{receiver_account(), "active"_n}});
        evmstake_act.send(make_key(msg.sender),make_key(sender_addr.bytes, kAddressLength), *dest_acc, dest_amount);


    } else if (app_type == 0xec8d3269) /* withdraw(address,uint256,address) */ {
        check(read_uint256(msg, 4) <= 0xffffFFFFffffFFFFffffFFFFffffFFFFffffFFFF_u256, "invalid destination address");
        evmc::address dest_addr;
        memcpy(dest_addr.bytes, (void *)&(msg.data[4 + 32 - kAddressLength]), kAddressLength);
        std::optional<uint64_t> dest_acc = silkworm::extract_reserved_address(dest_addr);
        check(!!dest_acc, "destination address in bridge_message_v0 must be reserved address");

        intx::uint256 value = read_uint256(msg, 4 + 32);
        intx::uint256 mult = intx::exp(10_u256, intx::uint256(delta_precision));
        check(value % mult == 0_u256, "bridge amount can not have dust");
        value /= mult;

        uint64_t dest_amount = (uint64_t)value;
        check(intx::uint256(dest_amount) == value && dest_amount < (1ull<<62)-1, "bridge amount value overflow");
        check(dest_amount > 0, "bridge amount must be positive");

        check(read_uint256(msg, 4 + 32 + 32) <= 0xffffFFFFffffFFFFffffFFFFffffFFFFffffFFFF_u256, "invalid sender address");
        evmc::address sender_addr;
        memcpy(sender_addr.bytes, (void *)&(msg.data[4 + 32 + 32 + 32 - kAddressLength]), kAddressLength);
        
        endrmng::evmunstake_action evmunstake_act(config.endrmng_account, {{receiver_account(), "active"_n}});
        evmunstake_act.send(make_key(msg.sender), make_key(sender_addr.bytes, kAddressLength), *dest_acc, dest_amount);

    }
    else {
        eosio::check(false, "unsupported bridge_message version");
    }

}

void evmutil::handle_utxo_access(const bridge_message_v0 &msg) {

}

void evmutil::handle_sync_rewards(const bridge_message_v0 &msg) {

    check(msg.data.size() >= 4, "not enough data in bridge_message_v0");

    uint32_t app_type = 0;
    memcpy((void *)&app_type, (const void *)&(msg.data[0]), sizeof(app_type));
    
    // 0x42b3c021 : 21c0b342 : claim(address,address)

    if (app_type == 0x42b3c021) {
        check(msg.data.size() >= 4 + 32 /*to*/ + 32 /*from*/, 
            "not enough data in bridge_message_v0 of application type 0x653332e5");

        auto read_uint256 = [&](const auto &msg, size_t offset) -> intx::uint256 {
            uint8_t buffer[32]={};
            check(msg.data.size() >= offset + 32, "not enough data in bridge_message_v0 of application type 0x42b3c021");
            memcpy(buffer, (void *)&(msg.data[offset]), 32);
            return intx::be::load<intx::uint256>(buffer);
        };

        check(read_uint256(msg, 4) <= 0xffffFFFFffffFFFFffffFFFFffffFFFFffffFFFF_u256, "invalid destination address");
        evmc::address dest_addr;
        memcpy(dest_addr.bytes, (void *)&(msg.data[4 + 32 - kAddressLength]), kAddressLength);
        std::optional<uint64_t> dest_acc = silkworm::extract_reserved_address(dest_addr);
        check(!!dest_acc, "destination address in bridge_message_v0 must be reserved address");

        check(read_uint256(msg, 4 + 32) <= 0xffffFFFFffffFFFFffffFFFFffffFFFFffffFFFF_u256, "invalid sender address");
        evmc::address sender_addr;
        memcpy(sender_addr.bytes, (void *)&(msg.data[4 + 32 + 32 - kAddressLength]), kAddressLength);

        // TODO: send request
        // eosio::token::transfer_action transfer_act(itr->token_contract, {{get_self(), "active"_n}});
        // transfer_act.send(get_self(), dest_eos_acct, eosio::asset(dest_amount, itr->ingress_fee.symbol), memo);

    
    } else {
        eosio::check(false, "unsupported bridge_message version");
    }
}

void evmutil::onbridgemsg(const bridge_message_t &message) {
    config_t config = get_config();

    check(get_sender() == config.evm_account, "invalid sender of onbridgemsg");

    const bridge_message_v0 &msg = std::get<bridge_message_v0>(message);
    check(msg.receiver == receiver_account(), "invalid message receiver");

    

    // Locate regular claim address
    util_contract_table_t contract_table(_self, _self.value);
    eosio::check(contract_table.begin() != contract_table.end(), "no implementaion contract available");
    auto contract_itr = contract_table.end();
    --contract_itr;

    if (contract_itr->address == msg.sender) {
        handle_sync_rewards(msg);
    }
    else {
        checksum256 addr_key = make_key(msg.sender);
        token_table_t token_table(_self, _self.value);
        auto index = token_table.get_index<"by.address"_n>();
        auto itr = index.find(addr_key);

        check(itr != index.end() && itr->address == msg.sender, "ERC-20 token not registerred");

        handle_endorser_stakes(msg, itr->erc20_precision - config.evm_gas_token_symbol.precision());
    }

}

void evmutil::transfer(eosio::name from, eosio::name to, eosio::asset quantity,
                     std::string memo) {
    eosio::check(false, "this address should not accept tokens");
}

void evmutil::setdepfee(eosio::name token_contract, std::string proxy_address, const eosio::asset &fee) {
    require_auth(get_self());

    config_t config = get_config();

    eosio::check(fee.symbol == config.evm_gas_token_symbol, "egress_fee should have native token symbol");

    auto address_bytes = from_hex(proxy_address);
    eosio::check(!!address_bytes, "token address must be valid 0x EVM address");
    eosio::check(address_bytes->size() == kAddressLength, "invalid length of token address");

    checksum256 addr_key = make_key(*address_bytes);
    token_table_t token_table(_self, _self.value);
    auto index = token_table.get_index<"by.address"_n>();
    auto token_table_iter = index.find(addr_key);

    check(token_table_iter != index.end() && token_table_iter->address == address_bytes, "ERC-20 token not registerred");
    
    intx::uint256 fee_evm = fee.amount;
    fee_evm *= get_minimum_natively_representable(config);

    auto pack_uint256 = [&](bytes &ds, const intx::uint256 &val) {
        uint8_t val_[32] = {};
        intx::be::store(val_, val);
        ds.insert(ds.end(), val_, val_ + sizeof(val_));
    };

    bytes call_data;
    // sha(setFee(uint256)) == 0x69fe0e2d
    uint8_t func_[4] = {0x69,0xfe,0x0e,0x2d};
    call_data.insert(call_data.end(), func_, func_ + sizeof(func_));
    pack_uint256(call_data, fee_evm);

    bytes value_zero; 
    value_zero.resize(32, 0);

    evm_runtime::call_action call_act(config.evm_account, {{receiver_account(), "active"_n}});
    call_act.send(receiver_account(), token_table_iter->address, value_zero, call_data, config.evm_gaslimit);
}

void evmutil::unregtoken(std::string proxy_address) {
    require_auth(get_self());

    auto proxy_address_bytes = from_hex(proxy_address);
    eosio::check(!!proxy_address_bytes, "token address must be valid 0x EVM address");
    eosio::check(proxy_address_bytes->size() == kAddressLength, "invalid length of token address");

    token_table_t token_table(_self, _self.value);
    auto index_symbol = token_table.get_index<"by.tokenaddr"_n>();
    auto token_table_iter = index_symbol.find(make_key(*proxy_address_bytes));
    eosio::check(token_table_iter != index_symbol.end(), "token not registered");

    index_symbol.erase(token_table_iter);
}

void evmutil::init(eosio::name evm_account, eosio::symbol gas_token_symbol, uint64_t gaslimit, uint64_t init_gaslimit) {
    require_auth(get_self());

    config_singleton_t config_table(get_self(), get_self().value);
    eosio::check(!config_table.exists(), "evmutil config already initialized");

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

void evmutil::setgaslimit(std::optional<uint64_t> gaslimit, std::optional<uint64_t> init_gaslimit) {
    require_auth(get_self());

    config_t config = get_config();
    if (gaslimit.has_value()) config.evm_gaslimit = *gaslimit;
    if (init_gaslimit.has_value()) config.evm_init_gaslimit = *init_gaslimit;
    set_config(config);
}

inline eosio::name evmutil::receiver_account()const {
    return get_self();
}

}  // namespace evmutil