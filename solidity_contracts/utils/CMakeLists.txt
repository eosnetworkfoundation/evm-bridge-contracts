
# Not necessarily used in code, but it's good to be here.
generate_solidity_bytecode_target(
   CONTRACT_NAME XBTC
   CONTRACT_SOURCE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/XBTC.sol"
   CONTRACT_NAMESPACE "XBTC"
   BYTECODE_HEADER_OUTPUT_PATH "${SOLIDITY_BYTECODES_DIR}/utils/xbtc_bytecode.hpp"
)

add_custom_target(GenerateUtilsBytecode ALL
   DEPENDS XBTC
)
