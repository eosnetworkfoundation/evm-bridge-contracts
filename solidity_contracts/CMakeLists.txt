add_subdirectory(compile_tools)

add_subdirectory(erc20)
add_subdirectory(utils)

add_custom_target(GenerateAllBytecode ALL
   DEPENDS GenerateErc20Bytecode
   DEPENDS GenerateUtilsBytecode
)
