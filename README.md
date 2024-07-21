# Exsat EVM supporting contracts

This repository contains the Solidity and Antelope contracts needed to support advanced functionality of the Exsat. Including trustless bridges, staking and reward claiming.

Those contracts (both within `solidity_contracts` and `antelope_contracts`) enable communication and tokens moves between the EVM and Native environments. 

## Dependencies

- CMake 3.16 or later
- [Leap](https://github.com/AntelopeIO/leap) 5.0 or later
- [CDT](https://github.com/AntelopeIO/cdt) 4.0 or later
- solc
  + Used to compile the .sol files. 
  + We chose to use solcjs because it is more actively maintained than the solc available from the package manager.
    * First install node.js and npm.
    * Then install solcjs: `npm install -g solc`
  + Make sure to install at least version 0.8.21.
    * Confirm with `solcjs --version`.
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
