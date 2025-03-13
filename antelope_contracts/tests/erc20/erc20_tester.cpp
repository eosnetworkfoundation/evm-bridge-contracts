#include "erc20_tester.hpp"

#include <contracts.hpp>
#include <cstdint>
#include <cstring>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/fixed_bytes.hpp>
#include <eosio/testing/tester.hpp>
#include <fc/crypto/hex.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/io/raw.hpp>
#include <fc/variant_object.hpp>
#include <intx/intx.hpp>

#include <erc20/bytecode.hpp>

#include <optional>

using namespace eosio;
using namespace eosio::chain;
using mvo = fc::mutable_variant_object;

using intx::operator""_u256;

namespace fc {

void to_variant(const intx::uint256& o, fc::variant& v)
{
   std::string output = intx::to_string(o, 10);
   v = std::move(output);
}

void to_variant(const evmc::address& o, fc::variant& v)
{
   std::string output = "0x";
   output += fc::to_hex((char*)o.bytes, sizeof(o.bytes));
   v = std::move(output);
}

} // namespace fc


namespace erc20_test {
const eosio::chain::symbol token_symbol(4u, "USDT");
const eosio::chain::symbol eos_token_symbol(4u, "EOS");
const eosio::chain::name gold_token_account("goldgoldgold"); // testing evm->native bridge
const eosio::chain::name evm_account("eosio.evm");
const eosio::chain::name faucet_account_name("eosio.faucet");
const eosio::chain::name erc20_account("eosio.erc2o");
const eosio::chain::name evmin_account("eosio.evmin");

evm_eoa::evm_eoa(std::basic_string<uint8_t> optional_private_key)
{
   if (optional_private_key.size() == 0) {
      // No private key specified. So randomly generate one.
      fc::rand_bytes((char*)private_key.data(), private_key.size());
   } else {
      if (optional_private_key.size() != 32) {
         throw std::runtime_error("private key provided to evm_eoa must be exactly 32 bytes");
      }
      std::memcpy(private_key.data(), optional_private_key.data(), private_key.size());
   }

   public_key.resize(65);

   secp256k1_pubkey pubkey;
   BOOST_REQUIRE(secp256k1_ec_pubkey_create(ctx, &pubkey, private_key.data()));

   size_t serialized_result_sz = public_key.size();
   secp256k1_ec_pubkey_serialize(ctx, public_key.data(), &serialized_result_sz, &pubkey, SECP256K1_EC_UNCOMPRESSED);

   BOOST_REQUIRE(public_key[0] == 4u);

   const union ethash_hash256 key_hash = ethash_keccak256(public_key.data() + 1, 64);
   memcpy(address.bytes, &key_hash.bytes[12], 20);
}

std::string evm_eoa::address_0x() const { return fc::variant(address).as_string(); }

key256_t evm_eoa::address_key256() const
{
   uint8_t buffer[32] = {0};
   memcpy(buffer, address.bytes, sizeof(address.bytes));
   return fixed_bytes<32>(buffer).get_array();
}

void evm_eoa::sign(silkworm::Transaction& trx) {
   sign(trx, evm_chain_id);
}

void evm_eoa::sign(silkworm::Transaction& trx, std::optional<uint64_t> evm_chain_id)
{
   silkworm::Bytes rlp;
   if(evm_chain_id.has_value())
      trx.chain_id = evm_chain_id.value();
   trx.nonce = next_nonce++;
   trx.encode_for_signing(rlp);
   //silkworm::rlp::encode(rlp, trx, true, false);
   ethash::hash256 hash{silkworm::keccak256(rlp)};

   secp256k1_ecdsa_recoverable_signature sig;
   BOOST_REQUIRE(secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash.bytes, private_key.data(), NULL, NULL));
   uint8_t r_and_s[64];
   int recid;
   secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, r_and_s, &recid, &sig);

   trx.r = intx::be::unsafe::load<intx::uint256>(r_and_s);
   trx.s = intx::be::unsafe::load<intx::uint256>(r_and_s + 32);
   trx.odd_y_parity = recid;
}

evm_eoa::~evm_eoa() { secp256k1_context_destroy(ctx); }




erc20_tester::erc20_tester(bool use_real_evm, eosio::chain::name evm_account_, std::string native_symbol_str, eosio::chain::name eos_token_account_) : evm_account(evm_account_), native_symbol(symbol::from_string(native_symbol_str)), eos_token_account(eos_token_account_) {
    auto def_conf = default_config(tempdir, 65536);

    cfg = def_conf.first;
    init(def_conf.first, def_conf.second, testing::call_startup_t::yes);

    const auto& pfm = control->get_protocol_feature_manager();

    auto preactivate_feature_digest = pfm.get_builtin_digest(builtin_protocol_feature_t::preactivate_feature);
    FC_ASSERT(preactivate_feature_digest, "PREACTIVATE_FEATURE not found");
    schedule_protocol_features_wo_preactivation({*preactivate_feature_digest});

    produce_block();

    set_code("eosio"_n, testing::contracts::eosio_boot_wasm());
    set_abi("eosio"_n, testing::contracts::eosio_boot_abi().data());

    preactivate_all_builtin_protocol_features();

    produce_block();

    create_accounts({eos_token_account, evm_account, token_account, faucet_account_name, erc20_account, gold_token_account});
    create_account(evmin_account, config::system_account_name, false, true);

    // eosio.token
    set_code(eos_token_account, testing::contracts::eosio_token_wasm());
    set_abi(eos_token_account, testing::contracts::eosio_token_abi().data());

    push_action(eos_token_account,
                "create"_n,
                eos_token_account,
                mvo()("issuer", eos_token_account)("maximum_supply", asset(10'000'000'000'0000, native_symbol)));
    push_action(eos_token_account,
                "issue"_n,
                eos_token_account,
                mvo()("to", faucet_account_name)("quantity", asset(1'000'000'000'0000, native_symbol))("memo", ""));
    produce_block();

    // tethertether
    set_code(token_account, testing::contracts::eosio_token_wasm());
    set_abi(token_account, testing::contracts::eosio_token_abi().data());

    push_action(token_account,
                "create"_n,
                token_account,
                mvo()("issuer", token_account)("maximum_supply", asset(10'000'000'000'0000, symbol::from_string("4,USDT"))));
    push_action(token_account,
                "issue"_n,
                token_account,
                mvo()("to", faucet_account_name)("quantity", asset(1'000'000'000'0000, symbol::from_string("4,USDT")))("memo", ""));

    // create and issue mirrored GOLD token to erc2o account
    set_code(gold_token_account, testing::contracts::eosio_token_wasm());
    set_abi(gold_token_account, testing::contracts::eosio_token_abi().data());

    push_action(gold_token_account,
                "create"_n,
                gold_token_account,
                mvo()("issuer", gold_token_account)("maximum_supply", asset(100'000'000'0000, symbol::from_string("4,GOLD"))));
    push_action(gold_token_account,
                "issue"_n,
                gold_token_account,
                mvo()("to", erc20_account)("quantity", asset(100'000'000'0000, symbol::from_string("4,GOLD")))("memo", erc20_account.to_string()));


    set_code(evmin_account, testing::contracts::evm_deposit_proxy_wasm());

    produce_block();

    set_code(erc20_account, testing::contracts::erc20_wasm());
    set_abi(erc20_account, testing::contracts::erc20_abi().data());

    produce_block();
    
    if (native_symbol_str.length()) {
        push_action(erc20_account, "init"_n, erc20_account, mvo("evm_account", evm_account)("gas_token_symbol", native_symbol_str)("gaslimit", 500000)("init_gaslimit", 10000000));

        BOOST_REQUIRE_EXCEPTION(
            push_action(erc20_account, "init"_n, erc20_account, mvo("evm_account", evm_account)("gas_token_symbol", native_symbol_str)("gaslimit", 1)("init_gaslimit", 1)),
            eosio_assert_message_exception, 
            testing::eosio_assert_message_is("erc20 config already initialized"));
    }

    if (use_real_evm) {
        set_code(evm_account, testing::contracts::evm_wasm());
        set_abi(evm_account, testing::contracts::evm_abi().data());

        produce_block();

        init_evm();

        produce_block();

        open(erc20_account);

        transfer_token(eos_token_account, faucet_account_name, evm_account, make_asset(10'0000'0000), "eosio.erc2o"); // 100K EOS or 10 BTC

        bridgereg(erc20_account, erc20_account, make_asset(100));
    } else {
        set_code(evm_account, testing::contracts::evm_stub_wasm());
        set_abi(evm_account, testing::contracts::evm_stub_abi().data());

        produce_block();

        push_action(evm_account,
                    "init"_n,
                    evm_account,
                    mvo());
        produce_block();
    }

    produce_block();

    evm_eoa deployer;
    impl_addr = silkworm::create_address(deployer.address, deployer.next_nonce); 

    if (use_real_evm) {
        try {

            transfer_token(eos_token_account, faucet_account_name, evm_account, make_asset(10'0000'0000), deployer.address_0x().c_str());

            auto txn = prepare_deploy_contract_tx(solidity::erc20::bytecode, sizeof(solidity::erc20::bytecode), 10'000'000);

            deployer.sign(txn);
            pushtx(txn);
            produce_block();

        } FC_CAPTURE_AND_RETHROW()
    }

    push_action(erc20_account, "upgradeto"_n, erc20_account, mvo()("impl_address",fc::variant(impl_addr).as_string()));

    produce_block();

    push_action(erc20_account, "regtoken"_n, erc20_account, mvo()("eos_contract_name",token_account.to_string())("evm_token_name","EVM USDT V1")("evm_token_symbol","WUSDT")("ingress_fee","0.0100 USDT")("egress_fee", make_asset(100))("erc20_precision",6));

    produce_block();

    auto abi = fc::json::from_string(testing::contracts::eosio_token_abi().data()).template as<abi_def>();
    token_abi_ser.set_abi(std::move(abi), abi_serializer::create_yield_function(abi_serializer_max_time));
}

eosio::chain::transaction_trace_ptr erc20_tester::transfer_token(eosio::chain::name token_account_name, eosio::chain::name from, eosio::chain::name to, eosio::chain::asset quantity, std::string memo) {
    return push_action(
        token_account_name, "transfer"_n, from, mvo()("from", from)("to", to)("quantity", quantity)("memo", memo));
}

void erc20_tester::init_evm(const uint64_t chainid,
                            const uint64_t gas_price,
                            const uint32_t miner_cut,
                            const std::optional<asset> ingress_bridge_fee,
                            const bool also_prepare_self_balance) {
    mvo fee_params;
    fee_params("gas_price", gas_price)("miner_cut", miner_cut);

    if (ingress_bridge_fee.has_value()) {
        fee_params("ingress_bridge_fee", *ingress_bridge_fee);
    } else {
        fee_params("ingress_bridge_fee", make_asset(0));
    }

    push_action(evm_account, "init"_n, evm_account, mvo()("chainid", chainid)("fee_params", fee_params)("token_contract", eos_token_account));

    if (also_prepare_self_balance) {
        prepare_self_balance();
    }
}

void erc20_tester::prepare_self_balance(uint64_t fund_amount) {
    // Ensure internal balance for evm_account_name has at least 1 EOS to cover max bridge gas fee with even high gas
    // price.
    transfer_token(eos_token_account, faucet_account_name, evm_account, make_asset(1000'0000), evm_account.to_string()); // 100K EOS or 0.1 BTC
}

transaction_trace_ptr erc20_tester::bridgereg(eosio::chain::name receiver, eosio::chain::name handler, eosio::chain::asset min_fee, vector<account_name> extra_signers) {

    if (extra_signers.size() == 1 && extra_signers[0] == ""_n) {
        extra_signers[0] = evm_account;
    }
    extra_signers.push_back(receiver);
    if (receiver != handler)
        extra_signers.push_back(handler);
    return erc20_tester::push_action(evm_account, "bridgereg"_n, extra_signers,
                                     mvo()("receiver", receiver)("handler", handler)("min_fee", min_fee));
}

void erc20_tester::open(name owner) { push_action(evm_account, "open"_n, owner, mvo()("owner", owner)); }

transaction_trace_ptr erc20_tester::exec(const exec_input& input, const std::optional<exec_callback>& callback) {
    auto binary_data = fc::raw::pack<exec_input, std::optional<exec_callback>>(input, callback);
    return erc20_tester::push_action(evm_account, "exec"_n, evm_account, bytes{binary_data.begin(), binary_data.end()}, DEFAULT_EXPIRATION_DELTA + (exec_count++) % 3500);
}

eosio::chain::action erc20_tester::get_action(account_name code, action_name acttype, std::vector<permission_level> auths,
                                              const bytes& data) const {
    try {
        const auto& acnt = control->get_account(code);
        auto abi = acnt.get_abi();
        eosio::chain::abi_serializer abis(abi, abi_serializer::create_yield_function(abi_serializer_max_time));

        string action_type_name = abis.get_action_type(acttype);
        FC_ASSERT(action_type_name != string(), "unknown action type ${a}", ("a", acttype));

        eosio::chain::action act;
        act.account = code;
        act.name = acttype;
        act.authorization = auths;
        act.data = data;
        return act;
    }
    FC_CAPTURE_AND_RETHROW()
}

transaction_trace_ptr erc20_tester::push_action(const account_name& code,
                                                const action_name& acttype,
                                                const account_name& actor,
                                                const bytes& data,
                                                uint32_t expiration,
                                                uint32_t delay_sec) {
    vector<permission_level> auths;
    auths.push_back(permission_level{actor, config::active_name});
    try {
        signed_transaction trx;
        trx.actions.emplace_back(get_action(code, acttype, auths, data));
        set_transaction_headers(trx, expiration, delay_sec);
        for (const auto& auth : auths) {
            trx.sign(get_private_key(auth.actor, auth.permission.to_string()), control->get_chain_id());
        }

        return push_transaction(trx);
    }
    FC_CAPTURE_AND_RETHROW((code)(acttype)(auths)(data)(expiration)(delay_sec))
}

transaction_trace_ptr erc20_tester::pushtx(const silkworm::Transaction& trx, name miner)
{
    if (miner == name()) miner = evm_account;
   silkworm::Bytes rlp;
   silkworm::rlp::encode(rlp, trx);

   bytes rlp_bytes;
   rlp_bytes.resize(rlp.size());
   memcpy(rlp_bytes.data(), rlp.data(), rlp.size());

   return push_action(evm_account, "pushtx"_n, miner, mvo()("miner", miner)("rlptx", rlp_bytes));
}

silkworm::Transaction
erc20_tester::generate_tx(const evmc::address& to, const intx::uint256& value, uint64_t gas_limit) const
{
   silkworm::Transaction r;

   r.type = silkworm::TransactionType::kLegacy;
      r.max_priority_fee_per_gas = suggested_gas_price;
      r.max_fee_per_gas = suggested_gas_price;
      r.gas_limit = gas_limit;
      r.to = to;
      r.value = value;
   return r;
}

silkworm::Transaction
erc20_tester::prepare_deploy_contract_tx(const unsigned char* contract, size_t size, uint64_t gas_limit) const
{
    silkworm::Transaction r;

    r.type = silkworm::TransactionType::kLegacy;
    r.max_priority_fee_per_gas = suggested_gas_price;
    r.max_fee_per_gas = suggested_gas_price;
    r.gas_limit = gas_limit;
    r.value = 0;
    r.data.resize(size);
    memcpy(r.data.data(), contract, size);
    return r;
}

void erc20_tester::deploy_test_erc20_token(evm_eoa& from) {
    unsigned char hexstr[] = {
/*
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

interface IERC20 {
    function totalSupply() external view returns (uint);
    function balanceOf(address account) external view returns (uint);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint);
    function approve(address spender, uint amount) external returns (bool);
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint value);
    event Approval(address indexed owner, address indexed spender, uint value);
}

contract GoldToken is IERC20 {

    uint256 public _totalSupply;
    string public symbol;
    uint8 public decimals;
    mapping(address => uint) public _balanceOf;
    mapping(address => mapping(address => uint)) public _allowance;

    constructor() {
        symbol = "GOLD";
        decimals = 18;
        _totalSupply = 1000000 * (10 ** uint256(decimals));
        _balanceOf[msg.sender] = _totalSupply;
    }

    function totalSupply() override external view returns (uint) {
        return _totalSupply;
    }

    function balanceOf(address account) override external view returns (uint) {
        return _balanceOf[account];
    }

    function allowance(address owner, address spender) override external view returns (uint) {
        return _allowance[owner][spender];
    }

    function transfer(address recipient, uint amount) override external returns (bool) {
            require(_balanceOf[msg.sender] >= amount, "overdrawn balance");
            _balanceOf[msg.sender] -= amount;
            _balanceOf[recipient] += amount;
            emit Transfer(msg.sender, recipient, amount);
        return true;
    }

    function approve(address spender, uint amount) override external returns (bool) {
        _allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) override external returns (bool) {
        require(_allowance[sender][msg.sender] >= amount, "overdrawn allowance");
        require(_balanceOf[sender] >= amount, "overdrawn balance");
        _allowance[sender][msg.sender] -= amount;
        _balanceOf[sender] -= amount;
        _balanceOf[recipient] += amount;
        emit Transfer(sender, recipient, amount);
        return true;
    }
}
*/
        "60806040523480156200001157600080fd5b506040518060400160405280600481526020017f474f4c44000000000000000000000000000000000000000000000000000000008152506001908162000058919062000372565b506012600260006101000a81548160ff021916908360ff160217905550600260009054906101000a900460ff1660ff16600a620000969190620005dc565b620f4240620000a691906200062d565b600081905550600054600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555062000678565b600081519050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806200017a57607f821691505b60208210810362000190576200018f62000132565b5b50919050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b600060088302620001fa7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82620001bb565b620002068683620001bb565b95508019841693508086168417925050509392505050565b6000819050919050565b6000819050919050565b6000620002536200024d62000247846200021e565b62000228565b6200021e565b9050919050565b6000819050919050565b6200026f8362000232565b620002876200027e826200025a565b848454620001c8565b825550505050565b600090565b6200029e6200028f565b620002ab81848462000264565b505050565b5b81811015620002d357620002c760008262000294565b600181019050620002b1565b5050565b601f8211156200032257620002ec8162000196565b620002f784620001ab565b8101602085101562000307578190505b6200031f6200031685620001ab565b830182620002b0565b50505b505050565b600082821c905092915050565b6000620003476000198460080262000327565b1980831691505092915050565b600062000362838362000334565b9150826002028217905092915050565b6200037d82620000f8565b67ffffffffffffffff81111562000399576200039862000103565b5b620003a5825462000161565b620003b2828285620002d7565b600060209050601f831160018114620003ea5760008415620003d5578287015190505b620003e1858262000354565b86555062000451565b601f198416620003fa8662000196565b60005b828110156200042457848901518255600182019150602085019450602081019050620003fd565b8683101562000444578489015162000440601f89168262000334565b8355505b6001600288020188555050505b505050505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60008160011c9050919050565b6000808291508390505b6001851115620004e757808604811115620004bf57620004be62000459565b5b6001851615620004cf5780820291505b8081029050620004df8562000488565b94506200049f565b94509492505050565b600082620005025760019050620005d5565b81620005125760009050620005d5565b81600181146200052b576002811462000536576200056c565b6001915050620005d5565b60ff8411156200054b576200054a62000459565b5b8360020a91508482111562000565576200056462000459565b5b50620005d5565b5060208310610133831016604e8410600b8410161715620005a65782820a905083811115620005a0576200059f62000459565b5b620005d5565b620005b5848484600162000495565b92509050818404811115620005cf57620005ce62000459565b5b81810290505b9392505050565b6000620005e9826200021e565b9150620005f6836200021e565b9250620006257fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8484620004f0565b905092915050565b60006200063a826200021e565b915062000647836200021e565b925082820262000657816200021e565b9150828204841483151762000671576200067062000459565b5b5092915050565b610e9d80620006886000396000f3fe608060405234801561001057600080fd5b50600436106100a95760003560e01c806370a082311161007157806370a082311461016857806395d89b4114610198578063a9059cbb146101b6578063cca3e832146101e6578063dd336c1214610216578063dd62ed3e14610246576100a9565b8063095ea7b3146100ae57806318160ddd146100de57806323b872dd146100fc578063313ce5671461012c5780633eaaf86b1461014a575b600080fd5b6100c860048036038101906100c39190610a4f565b610276565b6040516100d59190610aaa565b60405180910390f35b6100e6610368565b6040516100f39190610ad4565b60405180910390f35b61011660048036038101906101119190610aef565b610371565b6040516101239190610aaa565b60405180910390f35b610134610663565b6040516101419190610b5e565b60405180910390f35b610152610676565b60405161015f9190610ad4565b60405180910390f35b610182600480360381019061017d9190610b79565b61067c565b60405161018f9190610ad4565b60405180910390f35b6101a06106c5565b6040516101ad9190610c36565b60405180910390f35b6101d060048036038101906101cb9190610a4f565b610753565b6040516101dd9190610aaa565b60405180910390f35b61020060048036038101906101fb9190610b79565b6108f2565b60405161020d9190610ad4565b60405180910390f35b610230600480360381019061022b9190610c58565b61090a565b60405161023d9190610ad4565b60405180910390f35b610260600480360381019061025b9190610c58565b61092f565b60405161026d9190610ad4565b60405180910390f35b600081600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040516103569190610ad4565b60405180910390a36001905092915050565b60008054905090565b600081600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015610432576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161042990610ce4565b60405180910390fd5b81600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410156104b4576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104ab90610d50565b60405180910390fd5b81600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546105409190610d9f565b9250508190555081600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546105969190610d9f565b9250508190555081600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546105ec9190610dd3565b925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516106509190610ad4565b60405180910390a3600190509392505050565b600260009054906101000a900460ff1681565b60005481565b6000600360008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b600180546106d290610e36565b80601f01602080910402602001604051908101604052809291908181526020018280546106fe90610e36565b801561074b5780601f106107205761010080835404028352916020019161074b565b820191906000526020600020905b81548152906001019060200180831161072e57829003601f168201915b505050505081565b600081600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410156107d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107ce90610d50565b60405180910390fd5b81600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546108269190610d9f565b9250508190555081600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825461087c9190610dd3565b925050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516108e09190610ad4565b60405180910390a36001905092915050565b60036020528060005260406000206000915090505481565b6004602052816000526040600020602052806000526040600020600091509150505481565b6000600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006109e6826109bb565b9050919050565b6109f6816109db565b8114610a0157600080fd5b50565b600081359050610a13816109ed565b92915050565b6000819050919050565b610a2c81610a19565b8114610a3757600080fd5b50565b600081359050610a4981610a23565b92915050565b60008060408385031215610a6657610a656109b6565b5b6000610a7485828601610a04565b9250506020610a8585828601610a3a565b9150509250929050565b60008115159050919050565b610aa481610a8f565b82525050565b6000602082019050610abf6000830184610a9b565b92915050565b610ace81610a19565b82525050565b6000602082019050610ae96000830184610ac5565b92915050565b600080600060608486031215610b0857610b076109b6565b5b6000610b1686828701610a04565b9350506020610b2786828701610a04565b9250506040610b3886828701610a3a565b9150509250925092565b600060ff82169050919050565b610b5881610b42565b82525050565b6000602082019050610b736000830184610b4f565b92915050565b600060208284031215610b8f57610b8e6109b6565b5b6000610b9d84828501610a04565b91505092915050565b600081519050919050565b600082825260208201905092915050565b60005b83811015610be0578082015181840152602081019050610bc5565b60008484015250505050565b6000601f19601f8301169050919050565b6000610c0882610ba6565b610c128185610bb1565b9350610c22818560208601610bc2565b610c2b81610bec565b840191505092915050565b60006020820190508181036000830152610c508184610bfd565b905092915050565b60008060408385031215610c6f57610c6e6109b6565b5b6000610c7d85828601610a04565b9250506020610c8e85828601610a04565b9150509250929050565b7f6f766572647261776e20616c6c6f77616e636500000000000000000000000000600082015250565b6000610cce601383610bb1565b9150610cd982610c98565b602082019050919050565b60006020820190508181036000830152610cfd81610cc1565b9050919050565b7f6f766572647261776e2062616c616e6365000000000000000000000000000000600082015250565b6000610d3a601183610bb1565b9150610d4582610d04565b602082019050919050565b60006020820190508181036000830152610d6981610d2d565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000610daa82610a19565b9150610db583610a19565b9250828203905081811115610dcd57610dcc610d70565b5b92915050565b6000610dde82610a19565b9150610de983610a19565b9250828201905080821115610e0157610e00610d70565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b60006002820490506001821680610e4e57607f821691505b602082108103610e6157610e60610e07565b5b5091905056fea2646970667358221220ed43817867d22d674e8484738e80bfc095479ca48d729bc46e183ec059e6793b64736f6c63430008120033"
    };
    std::vector<uint8_t> bytes;
    bytes.resize(sizeof(hexstr)/2, 0);
    for (size_t i = 0; i <= sizeof(hexstr) / 2; ++i) {
        unsigned char v = 0, a = hexstr[i * 2], b = hexstr[i * 2 + 1];
        v = from_hex_digit(a);
        v <<= 4;
        v += from_hex_digit(b);
        bytes[i] = v;
    }
    silkworm::Transaction txn = prepare_deploy_contract_tx(&(bytes[0]), bytes.size(), 500'000'000);
    auto old_nonce = from.next_nonce;
    from.sign(txn);

    try {
        pushtx(txn);
    } FC_LOG_AND_RETHROW()
}

std::optional<evm_contract_account_t> erc20_tester::getEVMAccountInfo(uint64_t primary_id) {
    auto& db = const_cast<chainbase::database&>(control->db());

    const auto* existing_tid = db.find<table_id_object, by_code_scope_table>(
        boost::make_tuple(evm_account, evm_account, "account"_n));
    if (!existing_tid) {
        return {};
    }
    const auto* kv_obj = db.find<chain::key_value_object, chain::by_scope_primary>(
        boost::make_tuple(existing_tid->id, primary_id));

    if (kv_obj) {
        auto r = fc::raw::unpack<evm_contract_account_t>(
            kv_obj->value.data(),
            kv_obj->value.size());
        return r;
    }
    else return std::optional<evm_contract_account_t>{};
}

}  // namespace erc20_test