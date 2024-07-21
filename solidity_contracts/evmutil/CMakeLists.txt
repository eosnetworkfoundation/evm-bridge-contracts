# Not necessarily used in code, but it's good to be here.
generate_solidity_bytecode_target(
   CONTRACT_NAME StakeHelper
   CONTRACT_SOURCE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/stake_helper.sol"
   CONTRACT_NAMESPACE "stakehelper"
   BYTECODE_HEADER_OUTPUT_PATH "${SOLIDITY_BYTECODES_DIR}/evmutil/stake_helper_bytecode.hpp"
)

# Not necessarily used in code, but it's good to be here.
generate_solidity_bytecode_target(
   CONTRACT_NAME RewardHelper
   CONTRACT_SOURCE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/reward_helper.sol"
   CONTRACT_NAMESPACE "rewardhelper"
   BYTECODE_HEADER_OUTPUT_PATH "${SOLIDITY_BYTECODES_DIR}/evmutil/reward_helper_bytecode.hpp"
)
add_custom_target(GenerateEvmUtilBytecode ALL
   DEPENDS StakeHelper
   DEPENDS RewardHelper
)
