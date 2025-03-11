
#include <contracts.hpp>
#include <cstdint>
#include <cstring>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/fixed_bytes.hpp>
#include <eosio/testing/tester.hpp>
#include <fc/crypto/hex.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/variant_object.hpp>
#include <intx/intx.hpp>
#include <optional>
#include <string>
#include <vector>

#include "erc20_tester.hpp"
#include <erc20/bytecode.hpp>

using namespace eosio;
using namespace eosio::chain;
using namespace erc20_test;
using namespace eosio::testing;
using mvo = fc::mutable_variant_object;

using intx::operator""_u256;
constexpr size_t kAddressLength{20};

struct it_tester : erc20_tester {
    std::string address_str32(const evmc::address& x) {
        std::stringstream hex_ss;
        for (uint8_t c : x.bytes) {
            hex_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        int hex_length = hex_ss.str().length();

        std::stringstream ss;
        ss << std::setfill('0') << std::setw(64 - hex_length) << 0;
        for (uint8_t c : x.bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        return ss.str();
    }

    std::string uint256_str32(intx::uint256 x) {
        uint8_t buffer[32] = {};
        intx::be::store(buffer, x);

        std::stringstream ss;

        for (uint8_t c : buffer) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        return ss.str();
    }

    std::string int_str32(uint32_t x) {
        std::stringstream hex_ss;
        hex_ss << std::hex << x;
        int hex_length = hex_ss.str().length();

        std::stringstream ss;
        ss << std::setfill('0') << std::setw(64 - hex_length) << 0 << std::hex << std::uppercase << x;
        return ss.str();
    }

    std::string str_to_hex(const std::string& str) {
        std::stringstream ss;
        for (char c : str) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        return ss.str();
    }

    std::string data_str32(const std::string& str) {
        std::stringstream ss;
        ss << str;
        int ps = 64 - (str.length() % 64);
        if (ps == 64) {
            ps = 0;
        }
        ss << std::setw(ps) << std::setfill('0') << "";
        return ss.str();
    }

    std::string evm_address; // <- the ERC20-contract address in EVM side
    it_tester() : erc20_tester(true) {
        create_accounts({"alice"_n});
        transfer_token(eos_token_account, faucet_account_name, "alice"_n, make_asset(10000'0000));
        produce_block();
        transfer_token(token_account, faucet_account_name, "alice"_n, make_asset(10000'0000, token_symbol));
        produce_block();
        create_accounts({"bob"_n});
        transfer_token(eos_token_account, faucet_account_name, "bob"_n, make_asset(10000'0000));
        produce_block();
        transfer_token(token_account, faucet_account_name, "bob"_n, make_asset(10000'0000, token_symbol));

        produce_block();

        evm_address = getSolidityContractAddress();
        BOOST_REQUIRE_MESSAGE(evm_address.size() == 42, std::string("address wrong: ") + evm_address);

        // init();
    }

    std::string getSolidityContractAddress(uint64_t primary_id = 0) {
        auto r = getRegistedTokenInfo(primary_id);
        return vec_to_hex(r.address, true);
    }

    token_t getRegistedTokenInfo(uint64_t primary_id = 0) {
        auto& db = const_cast<chainbase::database&>(control->db());

        const auto* existing_tid = db.find<table_id_object, by_code_scope_table>(
            boost::make_tuple(erc20_account, erc20_account, "tokens"_n));
        if (!existing_tid) {
            return {};
        }
        const auto* kv_obj = db.find<chain::key_value_object, chain::by_scope_primary>(
            boost::make_tuple(existing_tid->id, primary_id));

        if (kv_obj) {
            auto r = fc::raw::unpack<token_t>(
                kv_obj->value.data(),
                kv_obj->value.size());
            return r;
        } 
        else return token_t();
    }

    std::optional<evm_contract_account_t> getEVMAccountInfo(uint64_t primary_id) {
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

    intx::uint256 egressFee(std::optional<exec_callback> callback = {}, std::optional<bytes> context = {}) {
        exec_input input;
        input.context = context;
        input.to = *erc20_test::from_hex(evm_address.c_str());
        BOOST_REQUIRE_MESSAGE(input.to.size() == 20, std::string("address wrong: ") + evm_address);

        bytes calldata;
        uint8_t func[4] = {0x6a, 0x03, 0x66, 0xbf};  // sha3(egressFee())[:4] = 6a0366bf

        calldata.insert(calldata.end(), func, func + 4);

        input.data = calldata;

        auto res = exec(input, callback);

        BOOST_REQUIRE(res);
        BOOST_REQUIRE(res->action_traces.size() == 1);

        // Since callback information was not provided the result of the
        // execution is returned in the action return_value
        auto out = fc::raw::unpack<exec_output>(res->action_traces[0].return_value);
        BOOST_REQUIRE(out.status == 0);
        BOOST_REQUIRE(out.data.size() == 32);

        auto result = intx::be::unsafe::load<intx::uint256>(reinterpret_cast<const uint8_t*>(out.data.data()));
        return result;
    }

    intx::uint256 balanceOf(const char* owner, std::optional<exec_callback> callback = {}, std::optional<bytes> context = {}) {
        exec_input input;
        input.context = context;
        input.to = *erc20_test::from_hex(evm_address.c_str());

        bytes calldata;
        uint8_t func[4] = {0x70, 0xa0, 0x82, 0x31};  // sha3(balanceOf(address))[:4] = 70a08231

        calldata.insert(calldata.end(), func, func + 4);
        auto dest_buffer = erc20_test::from_hex(owner);
        uint8_t value_buffer[32] = {};
        memcpy(value_buffer + 32 - kAddressLength, dest_buffer->data(), kAddressLength);

        calldata.insert(calldata.end(), value_buffer, value_buffer + 32);

        input.data = calldata;

        auto res = exec(input, callback);

        BOOST_REQUIRE(res);
        BOOST_REQUIRE(res->action_traces.size() == 1);

        // Since callback information was not provided the result of the
        // execution is returned in the action return_value
        auto out = fc::raw::unpack<exec_output>(res->action_traces[0].return_value);
        BOOST_REQUIRE(out.status == 0);
        BOOST_REQUIRE(out.data.size() == 32);

        auto result = intx::be::unsafe::load<intx::uint256>(reinterpret_cast<const uint8_t*>(out.data.data()));
        return result;
    }

   void deploy_gold_token_tx(evm_eoa& from) {
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
        auto r = pushtx(txn);
    }

    void bridgeTransferERC20(evm_eoa& from, evmc::address& to, intx::uint256 amount, std::string memo, intx::uint256 egressfee) {
        auto target = evmc::from_hex<evmc::address>(evm_address);
        auto txn = generate_tx(*target, egressfee, 500'000);
        // bridgeTransfer(address,uint256,string) = 73761828
        txn.data = evmc::from_hex("0x73761828").value();
        txn.data += evmc::from_hex(address_str32(to)).value();       // param1 (to: address)
        txn.data += evmc::from_hex(uint256_str32(amount)).value();   // param2 (amount: uint256)
        txn.data += evmc::from_hex(int_str32(96)).value();           // offset memo (data: bytes)
        txn.data += evmc::from_hex(int_str32(memo.size())).value();  // memo length
        if (!memo.empty()) {
            txn.data += evmc::from_hex(data_str32(str_to_hex(memo))).value();  // memo
        }

        auto old_nonce = from.next_nonce;
        from.sign(txn);

        try {
            auto r = pushtx(txn);
            // dlog("action trace: ${a}", ("a", r));
        } catch (...) {
            from.next_nonce = old_nonce;
            throw;
        }
    }

    void transferERC20(evm_eoa& from, const evmc::address& to, intx::uint256 amount) {
        auto target = evmc::from_hex<evmc::address>(evm_address);

        auto txn = generate_tx(*target, 0, 500'000);
        // transfer(address,uint256) = a9059cbb
        txn.data = evmc::from_hex("0xa9059cbb").value();
        txn.data += evmc::from_hex(address_str32(to)).value();      // param1 (to: address)
        txn.data += evmc::from_hex(uint256_str32(amount)).value();  // param2 (amount: uint256)

        auto old_nonce = from.next_nonce;
        from.sign(txn);

        try {
            auto r = pushtx(txn);
            // dlog("action trace: ${a}", ("a", r));
        } catch (...) {
            from.next_nonce = old_nonce;
            throw;
        }
    }

    void approveERC20(evmc::address erc20_contract_addr, evm_eoa& from, const evmc::address& spender, intx::uint256 amount) {

        auto txn = generate_tx(erc20_contract_addr, 0, 500'000);
        // approve(address spender, uint amount) = 0x095ea7b3
        txn.data = evmc::from_hex("0x095ea7b3").value();
        txn.data += evmc::from_hex(address_str32(spender)).value(); // param1 (spender: address)
        txn.data += evmc::from_hex(uint256_str32(amount)).value();  // param2 (amount: uint256)

        auto old_nonce = from.next_nonce;
        from.sign(txn);

        try {
            auto r = pushtx(txn);
            // dlog("action trace: ${a}", ("a", r));
        } catch (...) {
            from.next_nonce = old_nonce;
            throw;
        }
    }

};

BOOST_AUTO_TEST_SUITE(erc20_tests)

BOOST_FIXTURE_TEST_CASE(it_basic_transfer, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());

    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);

    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));

    produce_block();

    auto fee = egressFee();
    // received = 1000/1e6*1e4 = 10
    bridgeTransferERC20(evm1, addr_alice, 1000, "aaa", fee);
    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());

    BOOST_REQUIRE(bal == 989000);
    bal = get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount();

    BOOST_REQUIRE(99990010 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_upgrade, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());

    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);

    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));

    produce_block();

    auto fee = egressFee();
    // received = 1000/1e6*1e4 = 10
    bridgeTransferERC20(evm1, addr_alice, 1000, "aaa", fee);
    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());

    BOOST_REQUIRE(bal == 989000);
    bal = get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount();

    BOOST_REQUIRE(99990010 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());

    // upgrade 

    evm_eoa deployer;
    evmc::address impl_addr = silkworm::create_address(deployer.address, deployer.next_nonce); 

    transfer_token(eos_token_account, faucet_account_name, evmin_account, make_asset(1000000, eos_token_symbol), deployer.address_0x().c_str());

    auto txn = prepare_deploy_contract_tx(solidity::erc20::bytecode, sizeof(solidity::erc20::bytecode), 10'000'000);

    deployer.sign(txn);
    pushtx(txn);
    produce_block();

    push_action(erc20_account, "upgradeto"_n, erc20_account, mvo()("impl_address",fc::variant(impl_addr).as_string()));

    produce_block();

    push_action(erc20_account, "callupgrade"_n, erc20_account, mvo()("token_contract",token_account)("token_symbol",symbol::from_string("4,USDT")));

    produce_block();

    // Perform some basic tests again

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    bal = balanceOf(evm1.address_0x().c_str());

    BOOST_REQUIRE(bal == 989000 + 990000);

    fee = egressFee();
    // received = 1000/1e6*1e4 = 10
    bridgeTransferERC20(evm1, addr_alice, 1000, "aaa", fee);
    produce_block();

    bal = balanceOf(evm1.address_0x().c_str());

    BOOST_REQUIRE(bal == 989000 * 2);

}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_unregtoken, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());

    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);

    produce_block();

    // alice send 1.0000 USDT to evm1
    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    // evm1 has 0.990000 USDT
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 990000);

    // alice has 9999.0000 USDT
    BOOST_REQUIRE(9999'0000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());

    // unregtoken
    push_action(
        erc20_account, "unregtoken"_n, erc20_account, mvo()("eos_contract_name", token_account)("token_symbol_code", (std::string)(token_symbol.name())));

    // EOS->EVM not allowed after unregtoken
    BOOST_REQUIRE_EXCEPTION(
        transfer_token(token_account, "alice"_n, erc20_account, make_asset(20000, token_symbol), evm1.address_0x().c_str()),
        eosio_assert_message_exception, 
        eosio_assert_message_is("received unregistered token"));

    // EVM->EOS not allowed after unregtoken
    auto fee = egressFee();
    BOOST_REQUIRE_EXCEPTION(
        bridgeTransferERC20(evm1, addr_alice, 10000, "aaa", fee),
        eosio_assert_message_exception, 
        eosio_assert_message_is("ERC-20 token not registerred"));

    // register token again (imply a different ERC-EVM address)
    push_action(erc20_account, "regtoken"_n, erc20_account, mvo()("eos_contract_name",token_account.to_string())("evm_token_name","EVM USDT V2")("evm_token_symbol","WUSDT")("ingress_fee","0.0100 USDT")("egress_fee","0.0100 EOS")("erc20_precision",6));

    // EOS->EVM: alice transfer 2 USDT to evm1 in EVM (new ERC-EVM address)
    transfer_token(token_account, "alice"_n, erc20_account, make_asset(20000, token_symbol), evm1.address_0x().c_str());

    // alice has 9997.0000 USDT
    BOOST_REQUIRE(9997'0000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());

    // evm1 has 0.990000 USDT under the original ERC-20 address
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 990000);

    // refresh evm token address
    evm_address = getSolidityContractAddress();

    // evm1 has 1.990000 USDT under the new ERC-20 address
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 1990000);

    // EVM->EOS: evm1 tranfer 0.010000 USDT to alice
    bridgeTransferERC20(evm1, addr_alice, 10000, "aaa", fee);

    // evm1 has 1.980000 USDT under the new ERC-20 address
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 1980000);    

    // alice has 9997.0000 USDT
    BOOST_REQUIRE(9997'0100 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_regwithcode, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());

    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);

    produce_block();

    // alice send 1.0000 USDT to evm1
    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());

    // evm1 has 0.990000 USDT
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 990000);

    // alice has 9999.0000 USDT
    BOOST_REQUIRE(9999'0000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());

    // unregtoken
    push_action(
        erc20_account, "unregtoken"_n, erc20_account, mvo()("eos_contract_name", token_account)("token_symbol_code", (std::string)(token_symbol.name())));

    // EOS->EVM not allowed after unregtoken
    BOOST_REQUIRE_EXCEPTION(
        transfer_token(token_account, "alice"_n, erc20_account, make_asset(20000, token_symbol), evm1.address_0x().c_str()),
        eosio_assert_message_exception, 
        eosio_assert_message_is("received unregistered token"));

    // EVM->EOS not allowed after unregtoken
    auto fee = egressFee();
    BOOST_REQUIRE_EXCEPTION(
        bridgeTransferERC20(evm1, addr_alice, 10000, "aaa", fee),
        eosio_assert_message_exception, 
        eosio_assert_message_is("ERC-20 token not registerred"));

    // register token again (imply a different ERC-EVM address)
    push_action(erc20_account, "regwithcode"_n, erc20_account, mvo()("eos_contract_name",token_account.to_string())("impl_address",fc::variant(impl_addr).as_string())("evm_token_name","EVM USDT V2")("evm_token_symbol","WUSDT")("ingress_fee","0.0100 USDT")("egress_fee","0.0100 EOS")("erc20_precision",6));

    // EOS->EVM: alice transfer 2 USDT to evm1 in EVM (new ERC-EVM address)
    transfer_token(token_account, "alice"_n, erc20_account, make_asset(20000, token_symbol), evm1.address_0x().c_str());

    // alice has 9997.0000 USDT
    BOOST_REQUIRE(9997'0000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());

    // evm1 has 0.990000 USDT under the original ERC-20 address
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 990000);

    // refresh evm token address
    evm_address = getSolidityContractAddress();

    // evm1 has 1.990000 USDT under the new ERC-20 address
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 1990000);

    // EVM->EOS: evm1 tranfer 0.010000 USDT to alice
    bridgeTransferERC20(evm1, addr_alice, 10000, "aaa", fee);

    // evm1 has 1.980000 USDT under the new ERC-20 address
    BOOST_REQUIRE(balanceOf(evm1.address_0x().c_str()) == 1980000);    

    // alice has 9997.0000 USDT
    BOOST_REQUIRE(9997'0100 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_eos_to_evm, it_tester)
try {
    evm_eoa evm1;
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000); // +1000000 - 10000
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // -10000
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, erc20_account, make_asset(0, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("must transfer positive quantity"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();


    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, erc20_account, make_asset(10, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("deposit amount must be greater than ingress fee"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, erc20_account, make_asset(100, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("deposit amount must be greater than ingress fee"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(101, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990100); // 9900000 + (10100 - 10000)
    BOOST_REQUIRE(99989899 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 99990000 - 101
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9901, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(200, token_symbol));
    produce_block();

    // setting a lower gas limit, USDT(EOS)-> USDT(EVM) will fails
    push_action(erc20_account, "setgaslimit"_n, erc20_account, mvo("gaslimit", 21001)("init_gaslimit", 10000000));

    BOOST_REQUIRE_EXCEPTION(
        transfer_token(token_account, "alice"_n, erc20_account, make_asset(102, token_symbol), evm1.address_0x().c_str()),
        eosio_assert_message_exception, 
        eosio_assert_message_is("pre_validate_transaction error: 22 Intrinsic gas too low")
    );

    // set it back
    push_action(erc20_account, "setgaslimit"_n, erc20_account, mvo("gaslimit", 500000)("init_gaslimit", 10000000));
    transfer_token(token_account, "alice"_n, erc20_account, make_asset(103, token_symbol), evm1.address_0x().c_str());

}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_evm_to_eos, it_tester)
try {
    evm_eoa evm1;
    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000100, token_symbol), evm1.address_0x().c_str());
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 1000000000); // +1000010000 - 10000, 1000 USDT
    BOOST_REQUIRE(89999900 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    auto fee = egressFee();
    // received = 1000/1e6*1e4 = 10
    bridgeTransferERC20(evm1, addr_alice, 1000, "aaa", fee);
    BOOST_REQUIRE(999999000 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999910 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    BOOST_REQUIRE_EXCEPTION(bridgeTransferERC20(evm1, addr_alice, 0, "aaa", fee), 
                eosio_assert_message_exception, eosio_assert_message_is("bridge amount must be positive"));
    BOOST_REQUIRE(999999000 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999910 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    BOOST_REQUIRE_EXCEPTION(bridgeTransferERC20(evm1, addr_alice, 1, "aaa", fee), 
                eosio_assert_message_exception, eosio_assert_message_is("bridge amount can not have dust"));
    BOOST_REQUIRE(999999000 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999910 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    bridgeTransferERC20(evm1, addr_alice, 100, "aaa", fee);
    BOOST_REQUIRE(999998900 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999911 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    bridgeTransferERC20(evm1, addr_alice, 100, "aaa", fee+1); // revert
    BOOST_REQUIRE(999998900 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999911 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();

    bridgeTransferERC20(evm1, addr_alice, 100, "aaa", fee-1); // revert
    BOOST_REQUIRE(999998900 == balanceOf(evm1.address_0x().c_str()));
    BOOST_REQUIRE(89999911 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    produce_block();


}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_set_ingress_fee, it_tester)
try {
    evm_eoa evm1;
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000100, token_symbol), evm1.address_0x().c_str());
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 1000000000); // +1000010000 - 10000, 1000 USDT
    BOOST_REQUIRE(89999900 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    BOOST_REQUIRE(10000100 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount()); 
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(10000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    push_action(erc20_account, "setingressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("ingress_fee", make_asset(200, token_symbol)));

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000200, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 2000000000); // 1000000000 +1000020000 - 20000, 2000 USDT
    BOOST_REQUIRE(79999700 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    BOOST_REQUIRE(20000300 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(20000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(300, token_symbol));
    produce_block();

    // Change fee and try transfer again.
    push_action(erc20_account, "setingressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("ingress_fee", make_asset(0, token_symbol)));

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000000, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 3000000000); // +1000000000
    BOOST_REQUIRE(69999700 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    BOOST_REQUIRE(30000300 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount()); 
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(30000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(300, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "setingressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("ingress_fee", make_asset(0, symbol::from_string("4,USDC"))));,
            eosio_assert_message_exception, eosio_assert_message_is("token not registered"));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "setingressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("ingress_fee", make_asset(0, symbol::from_string("2,USDT"))));,
            eosio_assert_message_exception, eosio_assert_message_is("incorrect precision for registered token"));

}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_set_egress_fee, it_tester)
try {
    constexpr intx::uint256 minimum_natively_representable = intx::exp(10_u256, intx::uint256(18 - 4));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "setegressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("token_symbol_code", "USDT")("egress_fee", make_asset(50))),
        eosio_assert_message_exception, eosio_assert_message_is("egress fee must be at least as large as the receiver's minimum fee"));

    produce_block();

    BOOST_REQUIRE(100 * minimum_natively_representable == egressFee()); // was 0.01

    produce_block();
    // set to 0.5
    push_action(erc20_account, "setegressfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("token_symbol_code", "USDT")("egress_fee", make_asset(5000)));
    
    BOOST_REQUIRE(5000 * minimum_natively_representable == egressFee());

    produce_block();
   
    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "setegressfee"_n, evm_account, 
        mvo()("token_contract", token_account)("token_symbol_code", "USDT")("egress_fee", make_asset(1000))),
        missing_auth_exception, eosio::testing::fc_exception_message_starts_with("missing authority of eosio.erc2o"));


    produce_block();
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_withdraw_fees, it_tester)
try {
    evm_eoa evm1;
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();

    transfer_token(token_account, "alice"_n, erc20_account, make_asset(10000100, token_symbol), evm1.address_0x().c_str());
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 1000000000); // +1000010000 - 10000, 1000 USDT
    BOOST_REQUIRE(89999900 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 
    BOOST_REQUIRE(10000100 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount()); 
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(10000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(10000, token_symbol))("to", "alice"_n)("memo", "asd")),
        eosio_assert_message_exception, eosio_assert_message_is("overdrawn balance"));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(0, token_symbol))("to", "alice"_n)("memo", "asd")),
        eosio_assert_message_exception, eosio_assert_message_is("quantity must be positive"));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(100, symbol::from_string("4,USDC")))("to", "alice"_n)("memo", "asd")),
        eosio_assert_message_exception, eosio_assert_message_is("token not registered"));

    BOOST_REQUIRE_EXCEPTION(push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(100, symbol::from_string("2,USDT")))("to", "alice"_n)("memo", "asd")),
        eosio_assert_message_exception, eosio_assert_message_is("incorrect precision for registered token"));

    push_action(erc20_account, "withdrawfee"_n, erc20_account, 
        mvo()("token_contract", token_account)("quantity", make_asset(100, token_symbol))("to", "alice"_n)("memo", "asd"));
    
    BOOST_REQUIRE(bal == 1000000000); // +1000010000 - 10000, 1000 USDT
    BOOST_REQUIRE(90000000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); 
    BOOST_REQUIRE(10000000 == get_balance(erc20_account, token_account, symbol::from_string("4,USDT")).get_amount()); 
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(10000000, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(0, token_symbol));
}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_eos_to_evm_with_proxy, it_tester)
try {
    evm_eoa evm1;
    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(1000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();


    // USDT balance should be zero
    auto bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 0);
    produce_block();

    transfer_token(token_account, "alice"_n, evmin_account, make_asset(10000, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000); // +1000000 - 10000
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // -10000
    auto tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, evmin_account, make_asset(0, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("must transfer positive quantity"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();


    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, evmin_account, make_asset(10, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("deposit amount must be greater than ingress fee"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    BOOST_REQUIRE_EXCEPTION(transfer_token(token_account, "alice"_n, evmin_account, make_asset(100, token_symbol), evm1.address_0x().c_str()),
                            eosio_assert_message_exception, eosio_assert_message_is("deposit amount must be greater than ingress fee"));
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990000);
    BOOST_REQUIRE(99990000 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount());
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9900, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(100, token_symbol));
    produce_block();

    transfer_token(token_account, "alice"_n, evmin_account, make_asset(101, token_symbol), evm1.address_0x().c_str());
    bal = balanceOf(evm1.address_0x().c_str());
    BOOST_REQUIRE(bal == 990100); // 9900000 + (10100 - 10000)
    BOOST_REQUIRE(99989899 == get_balance("alice"_n, token_account, symbol::from_string("4,USDT")).get_amount()); // 99990000 - 101
    tokenInfo = getRegistedTokenInfo();
    BOOST_REQUIRE(tokenInfo.balance == make_asset(9901, token_symbol));
    BOOST_REQUIRE(tokenInfo.fee_balance == make_asset(200, token_symbol));
    produce_block();

}
FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(it_evm2native_bridge, it_tester)
try {
    auto str_to_bytes = [](const char pri_key[65]) -> std::basic_string<uint8_t> {
        std::basic_string<uint8_t> pri_key_bytes;
        pri_key_bytes.resize(32, 0);
        for (size_t i = 0; i < 32; ++i) {
            uint8_t v = from_hex_digit(pri_key[i * 2]);
            v <<= 4;
            v += from_hex_digit(pri_key[i * 2 + 1]);
            pri_key_bytes[i] = v;
        }
        return pri_key_bytes;
    };

    // address 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4
    evm_eoa evm1{str_to_bytes("503f38a9c967ed597e47fe25643985f032b072db8075426a92110f82df48dfcb")};
    BOOST_REQUIRE(evm1.address_0x() == "0x5b38da6a701c568545dcfcb03fcb875f56beddc4");

    // address 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2
    evm_eoa evm2{str_to_bytes("7e5bfb82febc4c2c8529167104271ceec190eafdca277314912eaabdb67c6e5f")};

    // track the number of evm account from evm runtime contract table
    size_t evm_account_total = 0;
    while (getEVMAccountInfo(evm_account_total).has_value()) ++evm_account_total;

    // Give evm1 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(10000000, eos_token_symbol), evm1.address_0x().c_str());
    produce_block();

    size_t evm1_account_id = evm_account_total;
    std::optional<evm_contract_account_t> acc = getEVMAccountInfo(evm1_account_id);
    BOOST_REQUIRE(acc.has_value()); // evm1 account created
    BOOST_REQUIRE(acc->address_0x() == "0x5b38da6a701c568545dcfcb03fcb875f56beddc4");

    // evm1 deploy gold ERC-20 contract (calculated address 0xd9145cce52d386f254917e481eb44e9943f39138)
    deploy_gold_token_tx(evm1);
    produce_block();

    // ensure deployment is ok
    std::optional<evm_contract_account_t> gold_evm_acc = getEVMAccountInfo(evm1_account_id + 1);
    BOOST_REQUIRE(gold_evm_acc.has_value()); // gold contract evm account created
    BOOST_REQUIRE(gold_evm_acc->code_id.has_value());
    BOOST_REQUIRE(gold_evm_acc->address_0x() == "0xd9145cce52d386f254917e481eb44e9943f39138");

    // upgdevm2nat
    push_action(erc20_account, "upgdevm2nat"_n, erc20_account, mvo());

    // before token 1 registerred
    BOOST_REQUIRE(getSolidityContractAddress(1) == "0x");

    // regevm2nat
    push_action(erc20_account, "regevm2nat"_n, erc20_account, 
        mvo()("erc20_token_address", gold_evm_acc->address_0x())
        ("native_token_contract", gold_token_account_name)
        ("ingress_fee", "0.1000 GOLD")
        ("egress_fee", make_asset(100, eos_token_symbol))
        ("erc20_precision", 18)
        ("override_impl_address", ""));

    // Give evm2 some EOS
    transfer_token(eos_token_account, "alice"_n, evm_account, make_asset(100000, eos_token_symbol), evm2.address_0x().c_str());
    produce_block();

    // refresh evm token address to transfer within EVM world (evm1->evm2), now evm2 has 1.234 GOLD
    evm_address = gold_evm_acc->address_0x();
    transferERC20(evm1, *(evmc::from_hex<evmc::address>(evm2.address_0x())), (uint64_t)(1'234'000'000'000'000'000));
        
    auto bal = balanceOf(evm2.address_0x().c_str());
    BOOST_REQUIRE(bal == 1'234'000'000'000'000'000);

    std::string proxy_address = getSolidityContractAddress(1);// <- proxy contract address
    evm_address = proxy_address;
    // refresh evm token address, using id 1 (proxy contract)
    BOOST_REQUIRE(proxy_address == "0x33b57dc70014fd7aa6e1ed3080eed2b619632b8e");

    // before calling bridge trnasfer, we need to approve the proxy contract as the spender
    approveERC20(*(evmc::from_hex<evmc::address>(gold_evm_acc->address_0x())),
                 evm2,
                 *(evmc::from_hex<evmc::address>(proxy_address)), // <- proxy contract address
                 (uint64_t)(1'000'000'000'000'000'000));

    auto addr_alice = silkworm::make_reserved_address("alice"_n.to_uint64_t());

    auto fee = egressFee();
    // EVM -> native
    bridgeTransferERC20(evm2, addr_alice, (uint64_t)700'000'000'000'000'000, "hello world", fee);
    produce_block();

    evm_address = gold_evm_acc->address_0x();
    bal = balanceOf(evm2.address_0x().c_str());
    BOOST_REQUIRE(bal == 534'000'000'000'000'000);

    BOOST_REQUIRE(7000 == get_balance("alice"_n, gold_token_account_name, symbol::from_string("4,GOLD")).get_amount());

    // native -> EVM, 0.2 GOLD (0.1 ingress fee)
    transfer_token(gold_token_account_name, "alice"_n, erc20_account, make_asset(2000, symbol::from_string("4,GOLD")), evm2.address_0x().c_str());

    evm_address = gold_evm_acc->address_0x();
    bal = balanceOf(evm2.address_0x().c_str());
    BOOST_REQUIRE(bal == 634'000'000'000'000'000);
}
FC_LOG_AND_RETHROW()


BOOST_AUTO_TEST_SUITE_END()
