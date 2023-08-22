cmake_minimum_required(VERSION 3.16)
# this project name is used later, be caution when changing it.
project(antelope_contracts)
find_package(cdt)

include(ExternalProject)

ExternalProject_Add(
   contracts
   SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/contracts/
   BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/contracts/
   CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CDT_ROOT}/lib/cmake/cdt/CDTWasmToolchain.cmake -DEXTERNAL_DIR=${EXTERNAL_DIR}
   UPDATE_COMMAND ""
   PATCH_COMMAND ""
   TEST_COMMAND ""
   INSTALL_COMMAND ""
   BUILD_ALWAYS 1
   DEPENDS GenerateBytecode
)

add_subdirectory (tests)