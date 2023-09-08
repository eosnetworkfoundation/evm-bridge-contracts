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




erc20_tester::erc20_tester(bool use_real_evm, std::string native_symbol_str) : native_symbol(symbol::from_string(native_symbol_str)) {
    auto def_conf = default_config(tempdir);
    def_conf.first.max_nonprivileged_inline_action_size = 256 * 1024;
    cfg = def_conf.first;
    init(def_conf.first, def_conf.second);

    const auto& pfm = control->get_protocol_feature_manager();

    auto preactivate_feature_digest = pfm.get_builtin_digest(builtin_protocol_feature_t::preactivate_feature);
    FC_ASSERT(preactivate_feature_digest, "PREACTIVATE_FEATURE not found");
    schedule_protocol_features_wo_preactivation({*preactivate_feature_digest});

    produce_block();

    set_code("eosio"_n, testing::contracts::eosio_boot_wasm());
    set_abi("eosio"_n, testing::contracts::eosio_boot_abi().data());

    preactivate_all_builtin_protocol_features();

    produce_block();

    create_accounts({eos_token_account, evm_account, token_account, faucet_account_name, erc20_account, evmtok_account});

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

    set_code(evmtok_account, testing::contracts::erc20_wasm());
    set_abi(evmtok_account, testing::contracts::erc20_abi().data());

    produce_block();

    if (use_real_evm) {
        set_code(evm_account, testing::contracts::evm_wasm());
        set_abi(evm_account, testing::contracts::evm_abi().data());

        produce_block();

        init_evm();

        produce_block();

        open(erc20_account);

        transfer_token(eos_token_account, faucet_account_name, evm_account, make_asset(10000'0000), "eosio.erc2o");
        bridgereg(erc20_account, evmtok_account, asset(100, symbol::from_string("4,EOS")));
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

    auto delegated_auth = authority(1, {},
                                    {{.permission = {evmtok_account, config::active_name}, .weight = 1}});

    set_authority(erc20_account, config::active_name, delegated_auth);

    produce_block();

    // ./cleos push action eosio.erc2o init '[0]' -p eosio.erc2o
    push_action(evmtok_account, "upgrade"_n, evmtok_account, mvo());

    produce_block();

    push_action(evmtok_account, "regtoken"_n, evmtok_account, mvo()("eos_contract_name", token_account.to_string())("evm_token_name", "EVM USDT V1")("evm_token_symbol", "WUSDT")("ingress_fee", "0.0100 USDT")("egress_fee", "0.0100 EOS")("erc20_precision", 6));

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
        fee_params("ingress_bridge_fee", fc::variant());
    }

    push_action(evm_account, "init"_n, evm_account, mvo()("chainid", chainid)("fee_params", fee_params));

    if (also_prepare_self_balance) {
        prepare_self_balance();
    }
}

void erc20_tester::prepare_self_balance(uint64_t fund_amount) {
    // Ensure internal balance for evm_account_name has at least 1 EOS to cover max bridge gas fee with even high gas
    // price.
    transfer_token(eos_token_account, faucet_account_name, evm_account, make_asset(1'0000), evm_account.to_string());
}

transaction_trace_ptr erc20_tester::bridgereg(eosio::chain::name receiver, eosio::chain::name handler, eosio::chain::asset min_fee, vector<account_name> extra_signers) {
    extra_signers.push_back(receiver);
    if (receiver != handler)
        extra_signers.push_back(handler);
    return erc20_tester::push_action(evm_account, "bridgereg"_n, extra_signers,
                                     mvo()("receiver", receiver)("handler", handler)("min_fee", min_fee));
}

void erc20_tester::open(name owner) { push_action(evm_account, "open"_n, owner, mvo()("owner", owner)); }

transaction_trace_ptr erc20_tester::exec(const exec_input& input, const std::optional<exec_callback>& callback) {
    auto binary_data = fc::raw::pack<exec_input, std::optional<exec_callback>>(input, callback);
    return erc20_tester::push_action(evm_account, "exec"_n, evm_account, bytes{binary_data.begin(), binary_data.end()});
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

std::string erc20_tester::getSolidityContractAddress() {
    auto& db = const_cast<chainbase::database&>(control->db());

    const auto* existing_tid = db.find<table_id_object, by_code_scope_table>(
        boost::make_tuple(evmtok_account, evmtok_account, "tokens"_n));
    if (!existing_tid) {
        return {};
    }
    const auto* kv_obj = db.find<chain::key_value_object, chain::by_scope_primary>(
        boost::make_tuple(existing_tid->id, 0));

    auto r = fc::raw::unpack<token_t>(
        kv_obj->value.data(),
        kv_obj->value.size());
    BOOST_TEST_MESSAGE(std::string("address size:") + std::to_string(r.address.size()));
    return vec_to_hex(r.address, true);
}

transaction_trace_ptr erc20_tester::pushtx(const silkworm::Transaction& trx, name miner)
{
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

}  // namespace erc20_test