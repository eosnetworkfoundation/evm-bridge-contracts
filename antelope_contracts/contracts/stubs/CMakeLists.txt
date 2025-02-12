
add_contract(  stub_evm_runtime stub_evm_runtime stub_evm_runtime.cpp )
target_include_directories( stub_evm_runtime PUBLIC )

target_compile_options(stub_evm_runtime PUBLIC --no-missing-ricardian-clause)

