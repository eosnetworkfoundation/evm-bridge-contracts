cmake_minimum_required(VERSION 3.16)
project(evm_bridge_contracts)

set(EXTERNAL_DIR ${CMAKE_SOURCE_DIR}/external)
add_subdirectory (solidity_contracts)
add_subdirectory (antelope_contracts)

