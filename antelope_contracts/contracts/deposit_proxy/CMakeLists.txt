add_contract( deposit_proxy deposit_proxy src/deposit_proxy.cpp )
target_include_directories( deposit_proxy PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include )
target_ricardian_directory( deposit_proxy ${CMAKE_CURRENT_SOURCE_DIR}/ricardian )
target_compile_options(deposit_proxy PUBLIC --no-missing-ricardian-clause)