generate_solidity_bytecode_target(
   CONTRACT_NAME BridgeERC20
   CONTRACT_SOURCE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/contract.sol"
   CONTRACT_NAMESPACE "erc20"
   BYTECODE_HEADER_OUTPUT_PATH "${SOLIDITY_BYTECODES_DIR}/erc20/bytecode.hpp"
)

generate_solidity_bytecode_target(
   CONTRACT_NAME Erc20Proxy
   CONTRACT_SOURCE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/proxy.sol"
   CONTRACT_NAMESPACE "proxy"
   BYTECODE_HEADER_OUTPUT_PATH "${SOLIDITY_BYTECODES_DIR}/erc20/proxy_bytecode.hpp"
)

generate_solidity_bytecode_target(
   CONTRACT_NAME Evm2Native
   CONTRACT_SOURCE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/evm2native.sol"
   CONTRACT_NAMESPACE "evm2native"
   BYTECODE_HEADER_OUTPUT_PATH "${SOLIDITY_BYTECODES_DIR}/erc20/evm2native_bytecode.hpp"
)

add_custom_target(GenerateErc20Bytecode ALL
   DEPENDS BridgeERC20
   DEPENDS Erc20Proxy
   DEPENDS Evm2Native
)
