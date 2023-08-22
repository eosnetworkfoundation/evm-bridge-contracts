project(erc20_tests)
cmake_minimum_required(VERSION 3.12)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")

find_package(eosio)

enable_testing()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/contracts.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/contracts.hpp)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${EXTERNAL_DIR}/silkworm/third_party/intx/include
)

add_eosio_test_executable( unit_test
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/erc20_tester.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/transfer_tests.cpp
)

# TODO: add back eos-vm-oc once change to disable EOS VM OC subjective limits during unit test are added
add_test(NAME erc20_tests COMMAND unit_test --report_level=detailed --color_output )
