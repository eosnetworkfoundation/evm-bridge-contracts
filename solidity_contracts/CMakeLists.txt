add_subdirectory(compile_tools)

add_subdirectory(erc20)

add_custom_target(GenerateAllBytecode ALL
   DEPENDS GenerateErc20Bytecode
)
