# evm-bridge-contracts
Contracts to support the trustless bridge of the EOS EVM
## Dependency
- cmake 3.16 or later
- install cdt
- solc: Used to compile the .sol file. We choose to use solcjs because it is more actively maintained then the solc from rpm.
    - Install node.js and npm
    - Install solcjs: 'npm install -g solc'

## How to Build
- cd to 'build' directory
- run the command 'cmake -Deosio_DIR={leap dir} ..'
- run the command 'make'

## How to Test
The build step above will build the test as well
- goto build/{contract project name}/test, we only have "erc2o" project for now.
- 'ctest'