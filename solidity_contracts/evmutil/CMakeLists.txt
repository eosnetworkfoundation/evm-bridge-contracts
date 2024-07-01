# Not necessarily used in code, but it's good to be here.
generate_solidity_bytecode_target(
   CONTRACT_NAME StakeHelper
   CONTRACT_SOURCE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/stakehelper.sol"
   CONTRACT_NAMESPACE "stakehelper"
   BYTECODE_HEADER_OUTPUT_PATH "${SOLIDITY_BYTECODES_DIR}/evmutil/stakehelper_bytecode.hpp"
)

# Not necessarily used in code, but it's good to be here.
generate_solidity_bytecode_target(
   CONTRACT_NAME ClaimRewardHelper
   CONTRACT_SOURCE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/claim_reward_helper.sol"
   CONTRACT_NAMESPACE "claimrewardhelper"
   BYTECODE_HEADER_OUTPUT_PATH "${SOLIDITY_BYTECODES_DIR}/evmutil/claim_reward_helper_bytecode.hpp"
)
add_custom_target(GenerateEvmUtilBytecode ALL
   DEPENDS StakeHelper
   DEPENDS ClaimRewardHelper
)
