cmake_minimum_required(VERSION 3.16)
project(evm_bridge_antelope_contracts)

find_package(cdt)

add_subdirectory(erc20)
add_subdirectory(stubs)
