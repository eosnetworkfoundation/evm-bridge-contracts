cmake_minimum_required(VERSION 3.16)
project(evm_bridge_contracts)
add_subdirectory (solidity)
include(ExternalProject)
# if no cdt root is given use default path
if(CDT_ROOT STREQUAL "" OR NOT CDT_ROOT)
   find_package(cdt)
endif()

ExternalProject_Add(
   erc2o_project
   SOURCE_DIR ${CMAKE_SOURCE_DIR}/contracts/erc2o/src
   BINARY_DIR ${CMAKE_BINARY_DIR}/erc2o
   CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CDT_ROOT}/lib/cmake/cdt/CDTWasmToolchain.cmake -DEXTERNAL_DIR=${CMAKE_SOURCE_DIR}/external
   UPDATE_COMMAND ""
   PATCH_COMMAND ""
   TEST_COMMAND ""
   INSTALL_COMMAND ""
   BUILD_ALWAYS 1
   DEPENDS GenerateBytecode
)

ExternalProject_Add(
   erc2o_tests_project
   SOURCE_DIR ${CMAKE_SOURCE_DIR}/contracts/erc2o/test/
   BINARY_DIR ${CMAKE_BINARY_DIR}/erc2o/test/
   CMAKE_ARGS -DEXTERNAL_DIR=${CMAKE_SOURCE_DIR}/external -Deosio_DIR=${eosio_DIR}
   UPDATE_COMMAND ""
   PATCH_COMMAND ""
   TEST_COMMAND ""
   INSTALL_COMMAND ""
   BUILD_ALWAYS 1
   DEPENDS erc2o_project
)

