cmake_minimum_required(VERSION 3.16)
project(evm_bridge_contracts)

set(EXTERNAL_DIR ${CMAKE_SOURCE_DIR}/external)
set(SOLIDITY_BYTECODES_DIR ${CMAKE_BINARY_DIR}/solidity_contracts/bytecodes)

file(MAKE_DIRECTORY ${SOLIDITY_BYTECODES_DIR})

add_subdirectory (solidity_contracts)

enable_testing()
add_subdirectory (antelope_contracts)
