cmake_minimum_required(VERSION 3.16)
project(evm_bridge_antelope_contracts)

find_package(cdt REQUIRED)

add_compile_definitions(ANTELOPE)

add_subdirectory(erc20)
add_subdirectory(evmutil)
add_subdirectory(stubs)
add_subdirectory(deposit_proxy)
