cmake_minimum_required(VERSION 3.16)
project(erc2o_solidity)
add_custom_command(
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/erc2o/contract.sol
   OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/erc2o_bytecode.hpp
   COMMAND cp -f ${CMAKE_CURRENT_SOURCE_DIR}/erc2o/contract.sol ${CMAKE_CURRENT_BINARY_DIR}/erc2o_contract.sol
   COMMAND solcjs --bin erc2o_contract.sol
   COMMAND echo -n [=[constexpr char bytecode[] = \"]=] > "${CMAKE_CURRENT_BINARY_DIR}/erc2o_bytecode.hpp"
   COMMAND cat "./erc2o_contract_sol_ERC20_Generated.bin" >> "${CMAKE_CURRENT_BINARY_DIR}/erc2o_bytecode.hpp"
   COMMAND echo [=[\"\;]=] >> "${CMAKE_CURRENT_BINARY_DIR}/erc2o_bytecode.hpp"
   )

add_custom_command(
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/erc2o/proxy.sol
   OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/erc2o_proxy_bytecode.hpp
   COMMAND cp -f ${CMAKE_CURRENT_SOURCE_DIR}/erc2o/proxy.sol ${CMAKE_CURRENT_BINARY_DIR}/erc2o_proxy.sol
   COMMAND solcjs --bin erc2o_proxy.sol
   COMMAND echo -n [=[constexpr char proxy_bytecode[] = \"]=] > "${CMAKE_CURRENT_BINARY_DIR}/erc2o_proxy_bytecode.hpp"
   COMMAND cat "./erc2o_contract_sol_ERC20_Generated.bin" >> "${CMAKE_CURRENT_BINARY_DIR}/erc2o_proxy_bytecode.hpp"
   COMMAND echo [=[\"\;]=] >> "${CMAKE_CURRENT_BINARY_DIR}/erc2o_proxy_bytecode.hpp"
   )

   add_custom_target(GenerateBytecode ALL
   DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/erc2o_bytecode.hpp
   DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/erc2o_proxy_bytecode.hpp
)