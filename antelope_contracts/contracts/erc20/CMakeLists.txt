cmake_minimum_required(VERSION 3.16)
project(erc20)

find_package(cdt)

set(SOURCES, "")

list(APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/erc2o.cpp
)

# ethash
list(APPEND SOURCES 
    ${EXTERNAL_DIR}/silkworm/third_party/ethash/lib/keccak/keccak.c
    ${EXTERNAL_DIR}/silkworm/third_party/ethash/lib/ethash/ethash.cpp
    ${EXTERNAL_DIR}/silkworm/third_party/ethash/lib/ethash/primes.c
)

# silkworm
list(APPEND SOURCES 
    ${EXTERNAL_DIR}/silkworm/silkworm/core/common/util.cpp
    ${EXTERNAL_DIR}/silkworm/silkworm/core/execution/address.cpp
    ${EXTERNAL_DIR}/silkworm/silkworm/core/common/endian.cpp
    ${EXTERNAL_DIR}/silkworm/silkworm/core/rlp/encode.cpp
    ${EXTERNAL_DIR}/silkworm/silkworm/core/rlp/decode.cpp
)


add_contract( erc2o erc2o ${SOURCES} )
target_include_directories( erc2o PUBLIC 
                            ${CMAKE_CURRENT_SOURCE_DIR}/include 
                            ${CMAKE_BINARY_DIR}/../../
                            ${EXTERNAL_DIR}/silkworm
                            ${EXTERNAL_DIR}/silkworm/third_party/intx/include 
                            ${EXTERNAL_DIR}/silkworm/third_party/ethash/include
                            ${EXTERNAL_DIR}/silkworm/third_party/evmone/include
                            ${EXTERNAL_DIR}/silkworm/third_party/evmone/lib
                            ${EXTERNAL_DIR}/silkworm/third_party/evmone/evmc/include
                            ${EXTERNAL_DIR}/expected/include    )
target_ricardian_directory( erc2o ${CMAKE_CURRENT_SOURCE_DIR}/ricardian )

target_compile_options(erc2o PUBLIC --no-missing-ricardian-clause)