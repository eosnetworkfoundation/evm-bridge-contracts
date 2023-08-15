cmake_minimum_required(VERSION 3.16)
project(erc2o)

find_package(cdt)

set(SOURCES, "")

list(APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/erc2o.cpp
)

# ethash
list(APPEND SOURCES 
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/third_party/ethash/lib/keccak/keccak.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/third_party/ethash/lib/ethash/ethash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/third_party/ethash/lib/ethash/primes.c
)

# silkworm
list(APPEND SOURCES 
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/silkworm/core/common/util.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/silkworm/core/execution/address.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/silkworm/core/common/endian.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/silkworm/core/rlp/encode.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/silkworm/core/rlp/decode.cpp
)


add_contract( erc2o erc2o ${SOURCES} )
target_include_directories( erc2o PUBLIC 
                            ${CMAKE_CURRENT_SOURCE_DIR}/../include 
                            ${CMAKE_BINARY_DIR}/../
                            ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm
                            ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/third_party/intx/include 
                            ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/third_party/ethash/include
                            ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/third_party/evmone/include
                            ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/third_party/evmone/lib
                            ${CMAKE_CURRENT_SOURCE_DIR}/../external/silkworm/third_party/evmone/evmc/include
                            ${CMAKE_CURRENT_SOURCE_DIR}/../external/expected/include    )
target_ricardian_directory( erc2o ${CMAKE_CURRENT_SOURCE_DIR}/../ricardian )

target_compile_options(erc2o PUBLIC --no-missing-ricardian-clause)