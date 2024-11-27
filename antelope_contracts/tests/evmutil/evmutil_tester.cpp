#include "evmutil_tester.hpp"

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

#include <utils/xbtc_bytecode.hpp>
#include <evmutil/stake_helper_bytecode.hpp>

#include <evmutil/reward_helper_bytecode.hpp>
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

void to_variant(const checksum256& o, fc::variant& v)
{
   std::string output;
   auto b = o.extract_as_byte_array();
   output += fc::to_hex((char*)b.data(), 32);
   v = std::move(output);
}

} // namespace fc


namespace evmutil_test {
const eosio::chain::symbol token_symbol(4u, "USDT");
const eosio::chain::symbol eos_token_symbol(8u, "BTC");
const eosio::chain::name evm_account("evm.xsat");
const eosio::chain::name faucet_account_name("faucet.xsat");
const eosio::chain::name evmutil_account("evmutil.xsat");


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




evmutil_tester::evmutil_tester(bool use_real_evm, eosio::chain::name evm_account_, std::string native_symbol_str) : evm_account(evm_account_), native_symbol(symbol::from_string(native_symbol_str)) {
    auto def_conf = default_config(tempdir, 4096);

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

    create_accounts({eos_token_account, evm_account, token_account, faucet_account_name, evmutil_account, btc_token_account, endrmng_account, poolreg_account});

    set_code(eos_token_account, testing::contracts::eosio_token_wasm());
    set_abi(eos_token_account, testing::contracts::eosio_token_abi().data());

    push_action(eos_token_account,
                "create"_n,
                eos_token_account,
                mvo()("issuer", eos_token_account)("maximum_supply", asset(10'000'000'000'00000000, native_symbol)));
    push_action(eos_token_account,
                "issue"_n,
                eos_token_account,
                mvo()("to", faucet_account_name)("quantity", asset(1'000'000'000'00000000, native_symbol))("memo", ""));
    produce_block();

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


    produce_block();
/*
    set_code(btc_token_account, testing::contracts::eosio_token_wasm());
    set_abi(btc_token_account, testing::contracts::eosio_token_abi().data());

    push_action(btc_token_account,
                "create"_n,
                btc_token_account,
                mvo()("issuer", btc_token_account)("maximum_supply", asset(10'000'000'000'00000000, symbol::from_string("8,BTC"))));
    push_action(btc_token_account,
                "issue"_n,
                btc_token_account,
                mvo()("to", faucet_account_name)("quantity", asset(1'000'000'000'00000000, symbol::from_string("8,BTC")))("memo", ""));
*/

    produce_block();


    set_code(evmutil_account, testing::contracts::evmutil_wasm());
    set_abi(evmutil_account, testing::contracts::evmutil_abi().data());

    produce_block();
    
    if (native_symbol_str.length()) {
        push_action(evmutil_account, "init"_n, evmutil_account, mvo("evm_account", evm_account)("gas_token_symbol", native_symbol_str)("gaslimit", 500000)("init_gaslimit", 10000000));

        BOOST_REQUIRE_EXCEPTION(
            push_action(evmutil_account, "init"_n, evmutil_account, mvo("evm_account", evm_account)("gas_token_symbol", native_symbol_str)("gaslimit", 1)("init_gaslimit", 1)),
            eosio_assert_message_exception, 
            testing::eosio_assert_message_is("evmutil config already initialized"));
    }

    if (use_real_evm) {
        set_code(evm_account, testing::contracts::evm_wasm());
        set_abi(evm_account, testing::contracts::evm_abi().data());

        produce_block();

        init_evm();

        produce_block();

        open(evmutil_account);

        transfer_token(eos_token_account, faucet_account_name, evm_account, make_asset(10000'00000000), "evmutil.xsat");
        auto r = bridgereg(evmutil_account, evmutil_account, asset(0, symbol::from_string("8,BTC")));
        // dlog("action trace: ${a}", ("a", r));
        produce_block();

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

    set_code(endrmng_account, testing::contracts::evm_stub_endrmng_wasm());
    set_abi(endrmng_account, testing::contracts::evm_stub_endrmng_abi().data());

    produce_block();

    set_code(poolreg_account, testing::contracts::evm_stub_poolreg_wasm());
    set_abi(poolreg_account, testing::contracts::evm_stub_poolreg_abi().data());

    produce_block();
    

    evm_eoa deployer;
    xbtc_addr = silkworm::create_address(deployer.address, deployer.next_nonce); 

    if (use_real_evm) {
        transfer_token(eos_token_account, faucet_account_name, evm_account, make_asset(10000000000, eos_token_symbol), deployer.address_0x().c_str());

        auto txn = prepare_deploy_contract_tx(solidity::XBTC::bytecode, sizeof(solidity::XBTC::bytecode), 10'000'000);

        deployer.sign(txn);
        pushtx(txn);
        produce_block();

        impl_addr = silkworm::create_address(deployer.address, deployer.next_nonce); 

        auto txn2 = prepare_deploy_contract_tx(solidity::stakehelper::bytecode, sizeof(solidity::stakehelper::bytecode), 10'000'000);

        deployer.sign(txn2);
        pushtx(txn2);
        produce_block();

        push_action(evmutil_account, "setstakeimpl"_n, evmutil_account, mvo()("impl_address",fc::variant(impl_addr).as_string()));

        produce_block();


        impl_addr = silkworm::create_address(deployer.address, deployer.next_nonce); 

        auto txn3 = prepare_deploy_contract_tx(solidity::rewardhelper::bytecode, sizeof(solidity::rewardhelper::bytecode), 10'000'000);

        deployer.sign(txn3);
        pushtx(txn3);
        produce_block();

        push_action(evmutil_account, "setrwdhelper"_n, evmutil_account, mvo()("impl_address",fc::variant(impl_addr).as_string()));

        produce_block();


    }

    push_action(evmutil_account, "regtoken"_n, evmutil_account, mvo()("token_address",fc::variant(xbtc_addr).as_string())("dep_fee","0.01000000 BTC")("erc20_precision",18));

    produce_block();

    auto abi = fc::json::from_string(testing::contracts::eosio_token_abi().data()).template as<abi_def>();
    token_abi_ser.set_abi(std::move(abi), abi_serializer::create_yield_function(abi_serializer_max_time));
}

eosio::chain::transaction_trace_ptr evmutil_tester::transfer_token(eosio::chain::name token_account_name, eosio::chain::name from, eosio::chain::name to, eosio::chain::asset quantity, std::string memo) {
    return push_action(
        token_account_name, "transfer"_n, from, mvo()("from", from)("to", to)("quantity", quantity)("memo", memo));
}

void evmutil_tester::init_evm(const uint64_t chainid,
                            const uint64_t gas_price,
                            const uint32_t miner_cut,
                            const std::optional<asset> ingress_bridge_fee,
                            const bool also_prepare_self_balance) {
    mvo fee_params;
    fee_params("gas_price", gas_price)("miner_cut", miner_cut);

    if (ingress_bridge_fee.has_value()) {
        fee_params("ingress_bridge_fee", *ingress_bridge_fee);
    } else {
        fee_params("ingress_bridge_fee", "0.00000000 BTC");
    }

    push_action(evm_account, "init"_n, evm_account, mvo()("chainid", chainid)("fee_params", fee_params));

    if (also_prepare_self_balance) {
        prepare_self_balance();
    }
}

void evmutil_tester::prepare_self_balance(uint64_t fund_amount) {
    // Ensure internal balance for evm_account_name has at least 1 EOS to cover max bridge gas fee with even high gas
    // price.
    transfer_token(eos_token_account, faucet_account_name, evm_account, make_asset(1'00000000), evm_account.to_string());
}

transaction_trace_ptr evmutil_tester::bridgereg(eosio::chain::name receiver, eosio::chain::name handler, eosio::chain::asset min_fee, vector<account_name> extra_signers) {
    extra_signers.push_back(receiver);
    if (receiver != handler)
        extra_signers.push_back(handler);
    return evmutil_tester::push_action(evm_account, "bridgereg"_n, extra_signers,
                                     mvo()("receiver", receiver)("handler", handler)("min_fee", min_fee));
}

void evmutil_tester::open(name owner) { push_action(evm_account, "open"_n, owner, mvo()("owner", owner)); }

transaction_trace_ptr evmutil_tester::exec(const exec_input& input, const std::optional<exec_callback>& callback) {
    auto binary_data = fc::raw::pack<exec_input, std::optional<exec_callback>>(input, callback);
    return evmutil_tester::push_action(evm_account, "exec"_n, evm_account, bytes{binary_data.begin(), binary_data.end()}, DEFAULT_EXPIRATION_DELTA + (exec_count++) % 3500);
}

eosio::chain::action evmutil_tester::get_action(account_name code, action_name acttype, std::vector<permission_level> auths,
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

transaction_trace_ptr evmutil_tester::push_action(const account_name& code,
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

transaction_trace_ptr evmutil_tester::pushtx(const silkworm::Transaction& trx, name miner)
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
evmutil_tester::generate_tx(const evmc::address& to, const intx::uint256& value, uint64_t gas_limit) const
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
evmutil_tester::prepare_deploy_contract_tx(const unsigned char* contract, size_t size, uint64_t gas_limit) const
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

}  // namespace erc20_test