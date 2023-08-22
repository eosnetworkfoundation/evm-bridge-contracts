cmake_minimum_required(VERSION 3.16)
project(erc20_solidity)
add_custom_command(
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/contract.sol
   OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/erc20_bytecode.hpp
   COMMAND cp -f ${CMAKE_CURRENT_SOURCE_DIR}/contract.sol ${CMAKE_CURRENT_BINARY_DIR}/erc20_contract.sol
   COMMAND solcjs --bin erc20_contract.sol
   COMMAND echo -n [=[constexpr char bytecode[] = \"]=] > "${CMAKE_CURRENT_BINARY_DIR}/erc20_bytecode.hpp"
   COMMAND cat "./erc20_contract_sol_BridgeERC20.bin" >> "${CMAKE_CURRENT_BINARY_DIR}/erc20_bytecode.hpp"
   COMMAND echo [=[\"\;]=] >> "${CMAKE_CURRENT_BINARY_DIR}/erc20_bytecode.hpp"
   )

add_custom_command(
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proxy.sol
   OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/erc20_proxy_bytecode.hpp
   COMMAND cp -f ${CMAKE_CURRENT_SOURCE_DIR}/proxy.sol ${CMAKE_CURRENT_BINARY_DIR}/erc20_proxy.sol
   COMMAND solcjs --bin erc20_proxy.sol
   COMMAND echo -n [=[constexpr char proxy_bytecode[] = \"]=] > "${CMAKE_CURRENT_BINARY_DIR}/erc20_proxy_bytecode.hpp"
   COMMAND cat "./erc20_proxy_sol_Erc20Proxy.bin" >> "${CMAKE_CURRENT_BINARY_DIR}/erc20_proxy_bytecode.hpp"
   COMMAND echo [=[\"\;]=] >> "${CMAKE_CURRENT_BINARY_DIR}/erc20_proxy_bytecode.hpp"
   )

   add_custom_target(GenerateBytecode ALL
   DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/erc20_bytecode.hpp
   DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/erc20_proxy_bytecode.hpp
)