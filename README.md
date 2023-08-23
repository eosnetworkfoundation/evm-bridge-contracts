# evm-bridge-contracts
Contracts to support the trustless bridge of the EOS EVM
## Dependency
- cmake 3.16 or later
- leap 4.0 or later
  - currently there's an issue in the v4.0 release of leap that will make it failed to build with c++20. Please either use the main branch of leap or manually apply the fix mentioned in https://github.com/AntelopeIO/leap/issues?page=2&q=is%3Aissue+is%3Aopen for v4.0 branch. 
- cdt 4.0 or later
- solc: Used to compile the .sol file. We choose to use solcjs because it is more actively maintained then the solc from rpm.
    - Install node.js and npm
    - Install solcjs: 'npm install -g solc'

## How to Build
- cd to 'build' directory
- run the command 'cmake -Dleap_DIR={leap dir} -Dcdt_DIR={cdt dir} ..'
  - use -Dleap_DIR and -Dcdt_DIR for custom builds of leap and cdt. The program will build with installed ones if they are not set.
- run the command 'make'

## How to Test
The build step above will build the test as well
- goto ./build
- 'ctest'