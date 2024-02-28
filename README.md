# EOS EVM Bridge Contracts

This repository contains the Solidity and Antelope contracts needed to support advanced functionality of the trustless bridge of EOS EVM.

The `erc20` contracts (both within `solidity_contracts` and `antelope_contracts`) enable tokens to be moved between the EOS EVM and EOS Native environments across the trustless bridge of EOS EVM. On the EOS EVM side, the tokens are managed by an ERC-20 compatible token contract that is automatically deployed to EOS EVM and managed by the Antelope `erc20` contract. On the EOS Native side, the Antelope `erc20` contract supports any tokens that follow the common interface established by the [`eosio.token` reference contract](https://github.com/AntelopeIO/reference-contracts/tree/main/contracts/eosio.token); specifically, the token contract deployed on EOS Native must satisfy the interface for the `transfer` action captured in [this header file](antelope_contracts/contracts/erc20/include/erc20/eosio.token.hpp) and its behavior should follow the expectations set in the `eosio.token` reference contract.
## Dependencies

- CMake 3.16 or later
- [Leap](https://github.com/AntelopeIO/leap) 5.0 or later
- [CDT](https://github.com/AntelopeIO/cdt) 4.0 or later
- solc
  + Used to compile the .sol files. 
  + We chose to use solcjs because it is more actively maintained than the solc available from the package manager.
    * First install node.js and npm.
    * Then install solcjs: `npm install -g solc@0.8.21`
  + Make sure to install version 0.8.21.
    * Confirm with `solcjs --version`. You should get `0.8.21+commit.d9974bed.Emscripten.clang`
- Install `jq` used to compile solidity contracts
  + `apt-get install jq`
- Install `xxd` used to compile solidity contracts
  + `apt-get install xxd`

## Building

Update submodules by running: `git submodule update --init --recursive`

Create a `build` directory within the root of the cloned repo and `cd` into it.

Run `cmake -Dleap_DIR="${LEAP_BUILD_PATH}/lib/cmake/leap" -Dcdt_DIR="${CDT_BUILD_PATH}/lib/cmake/cdt" ..` from within the `build` directory. 
Here we assume that environment variables `LEAP_BUILD_PATH` and `CDT_BUILD_PATH` are set to the build directories for the Leap and CDT dependencies, respectively.
The `-Dleap_DIR` and `-Dcdt_DIR` options are used to specify custom builds of Leap and CDT, respectively. If you have installed the appropriate version of CDT on the system, you can leave off the `-Dcdt_DIR`. Even if you have installed Leap binaries on the system, you will still need to build Leap and use `-Dleap_DIR` because the build directory contains specific testing libraries needed for building the unit tests for the bridge contracts.

Run the command `make -j`.

## Running tests

The build steps above will build the test as well.

After building, `cd` into the `build` directory and then simply run `ctest`.
