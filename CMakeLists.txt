cmake_minimum_required(VERSION 3.16)
project(evm_bridge_contracts)

if(NOT DEFINED eosevm_DIR)
    message(FATAL_ERROR "The `eosevm_DIR` argument was not provided!")
endif()

set(EXTERNAL_DIR ${CMAKE_SOURCE_DIR}/external)
set(SOLIDITY_BYTECODES_DIR ${CMAKE_BINARY_DIR}/solidity_contracts/bytecodes)

add_compile_definitions(PROJECT_VERSION="0.2.0")

add_subdirectory (solidity_contracts)

enable_testing()
add_subdirectory (antelope_contracts)
