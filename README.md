# Vaulta EVM Bridge Contracts

This repository contains the Solidity and Antelope contracts needed to support advanced functionality of the trustless bridge of Vaulta EVM.

The `erc20` contracts (both within `solidity_contracts` and `antelope_contracts`) enable tokens to be moved between the Vaulta EVM and Vaulta Native environments across the trustless bridge of Vaulta EVM. On the Vaulta EVM side, the tokens are managed by an ERC-20 compatible token contract that is automatically deployed to Vaulta EVM and managed by the Antelope `erc20` contract. On the Vaulta Native side, the Antelope `erc20` contract supports any tokens that follow the common interface established by the [`eosio.token` reference contract](https://github.com/AntelopeIO/reference-contracts/tree/main/contracts/eosio.token); specifically, the token contract deployed on Vaulta Native must satisfy the interface for the `transfer` action captured in [this header file](antelope_contracts/contracts/erc20/include/erc20/eosio.token.hpp) and its behavior should follow the expectations set in the `eosio.token` reference contract.

## Dependencies

- [Spring] (https://github.com/AntelopeIO/spring) 1.1 or greater
- [CDT Compiler] (https://github.com/AntelopeIO/cdt) 4.0 or greater
- [Vaulta EVM runtime contract] (https://github.com/VaultaFoundation/evm-contract) 
- solc: (version 0.8.21 or greater)
  + Used to compile the .sol files. 
  + We chose to use solcjs because it is more actively maintained than the solc available from the package manager.
    * First install node.js and npm.
    * Then install solcjs: for example, `npm install -g solc@0.8.21`
- Install `jq` used to compile solidity contracts
  + `apt-get install jq`
- Install `xxd` used to compile solidity contracts
  + `apt-get install xxd`

## Building the EVM bridge contract

```
git submodule update --init --recursive

mkdir build
cd build

export eosevm_DIR=<EVM_RUNTIME_BUILD_DIRECTORY>

cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -Deosevm_DIR=<EVM_RUNTIME_BUILD_DIRECTORY> -Dspring_DIR=<SPRING_DIRECTORY> -Dcdt_DIR=<CDT_DIRECTORY> .. && make -j8

```

You will get the wasm and abi at:
```
./build/antelope_contracts/contracts/erc20/erc20.wasm
./build/antelope_contracts/contracts/erc20/erc20.abi
```


## Running tests

```
cd build && ctest --output-on-failure --verbose 
```

## Design details and deployment steps

Please refer to https://github.com/VaultaFoundation/evm-public-docs/tree/main/Trustless_bridge
