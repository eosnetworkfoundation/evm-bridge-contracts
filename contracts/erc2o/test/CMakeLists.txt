project(erc2o_tests)
cmake_minimum_required(VERSION 3.12)


include(ExternalProject)

ExternalProject_Add(
   erc2o_stubs
   SOURCE_DIR ${CMAKE_SOURCE_DIR}/stubs/
   BINARY_DIR ${CMAKE_BINARY_DIR}/stubs
   CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CDT_ROOT}/lib/cmake/cdt/CDTWasmToolchain.cmake -DEXTERNAL_DIR=${CMAKE_SOURCE_DIR}/external
   UPDATE_COMMAND ""
   PATCH_COMMAND ""
   TEST_COMMAND ""
   INSTALL_COMMAND ""
   BUILD_ALWAYS 1
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")

find_package(eosio)

enable_testing()

configure_file(${CMAKE_SOURCE_DIR}/contracts.hpp.in ${CMAKE_BINARY_DIR}/contracts.hpp)

include_directories(
    ${CMAKE_BINARY_DIR}
    ${EXTERNAL_DIR}/silkworm/third_party/intx/include
)

add_eosio_test_executable( unit_test
    ${CMAKE_SOURCE_DIR}/main.cpp
    ${CMAKE_SOURCE_DIR}/erc2o_tester.cpp
    ${CMAKE_SOURCE_DIR}/transfer_tests.cpp
)

# TODO: add back eos-vm-oc once change to disable EOS VM OC subjective limits during unit test are added
add_test(NAME erc2o_tests COMMAND unit_test --report_level=detailed --color_output )
