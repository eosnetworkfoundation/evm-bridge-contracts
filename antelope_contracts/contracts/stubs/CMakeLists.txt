
add_contract(  stub_evm_runtime stub_evm_runtime stub_evm_runtime.cpp )
target_include_directories( stub_evm_runtime PUBLIC )

target_compile_options(stub_evm_runtime PUBLIC --no-missing-ricardian-clause)

add_contract(  stub_endrmng stub_endrmng stub_endrmng.cpp )
target_include_directories( stub_endrmng PUBLIC )

target_compile_options(stub_endrmng PUBLIC --no-missing-ricardian-clause)
