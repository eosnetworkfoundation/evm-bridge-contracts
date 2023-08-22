cmake_minimum_required(VERSION 3.16)
project(stubs_antelope)

find_package(cdt)

set(SOURCES, "")

list(APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/stub_evm_runtime.cpp
)

add_contract(  stub_evm_runtime stub_evm_runtime ${SOURCES} )
target_include_directories( stub_evm_runtime PUBLIC 
                            ${CMAKE_CURRENT_SOURCE_DIR}/include 
                            ${CMAKE_BINARY_DIR}/  )
