set(SOURCES, "")

list(APPEND SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/stub_evm_runtime.cpp
)

add_contract(  stub_evm_runtime stub_evm_runtime ${SOURCES} )
target_include_directories( stub_evm_runtime PUBLIC )

target_compile_options(stub_evm_runtime PUBLIC --no-missing-ricardian-clause)
