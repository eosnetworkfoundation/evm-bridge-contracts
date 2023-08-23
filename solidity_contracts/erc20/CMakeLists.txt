file(MAKE_DIRECTORY ${SOLIDITY_BYTECODES_DIR}/erc20)

set(BYTECODE_PATH ${SOLIDITY_BYTECODES_DIR}/erc20/bytecode.hpp )
add_custom_command(
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/contract.sol
   OUTPUT ${BYTECODE_PATH}
   COMMAND cp -f ${CMAKE_CURRENT_SOURCE_DIR}/contract.sol ${CMAKE_CURRENT_BINARY_DIR}/contract.sol
   COMMAND solcjs --bin contract.sol
   COMMAND echo -n [=[constexpr char bytecode[] = \"]=] > "${BYTECODE_PATH}"
   COMMAND cat "./contract_sol_BridgeERC20.bin" >> "${BYTECODE_PATH}"
   COMMAND echo [=[\"\;]=] >> "${BYTECODE_PATH}"
   )

set(PROXY_BYTECODE_PATH ${SOLIDITY_BYTECODES_DIR}/erc20/proxy_bytecode.hpp )
add_custom_command(
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proxy.sol
   OUTPUT ${PROXY_BYTECODE_PATH}
   COMMAND cp -f ${CMAKE_CURRENT_SOURCE_DIR}/proxy.sol ${CMAKE_CURRENT_BINARY_DIR}/proxy.sol
   COMMAND solcjs --bin proxy.sol
   COMMAND echo -n [=[constexpr char proxy_bytecode[] = \"]=] > "${PROXY_BYTECODE_PATH}"
   COMMAND cat "./proxy_sol_Erc20Proxy.bin" >> "${PROXY_BYTECODE_PATH}"
   COMMAND echo [=[\"\;]=] >> "${PROXY_BYTECODE_PATH}"
   )

add_custom_target(GenerateErc20Bytecode ALL
   DEPENDS ${BYTECODE_PATH}
   DEPENDS ${PROXY_BYTECODE_PATH}
   )
