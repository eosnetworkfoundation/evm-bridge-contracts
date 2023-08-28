file(MAKE_DIRECTORY ${SOLIDITY_BYTECODES_DIR}/erc20)

set(CONTRACT_NAME BridgeERC20)
set(CONTRACT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/contract.sol)
set(CONTRACT_NAMESPACE erc20) 
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/solcinput.json.in  ${CMAKE_CURRENT_BINARY_DIR}/contract_config.json)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/header_template.hpp.in  ${CMAKE_CURRENT_BINARY_DIR}/contract_header.hpp)


set(CONTRACT_NAME Erc20Proxy)
set(CONTRACT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/proxy.sol)
set(CONTRACT_NAMESPACE proxy) 
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/solcinput.json.in  ${CMAKE_CURRENT_BINARY_DIR}/proxy_config.json)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/header_template.hpp.in  ${CMAKE_CURRENT_BINARY_DIR}/proxy_header.hpp)

file(
    COPY ${CMAKE_CURRENT_SOURCE_DIR}/compile_command.sh
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
    FILE_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
    
)

set(BYTECODE_PATH ${SOLIDITY_BYTECODES_DIR}/erc20/bytecode.hpp )
add_custom_command(
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/contract.sol
   OUTPUT ${BYTECODE_PATH}
   COMMAND sh compile_command.sh "${CMAKE_CURRENT_SOURCE_DIR}/contract.sol" "${CMAKE_CURRENT_BINARY_DIR}/contract_config.json" "${CMAKE_CURRENT_BINARY_DIR}/contract_header.hpp" > "${BYTECODE_PATH}"
   )

set(PROXY_BYTECODE_PATH ${SOLIDITY_BYTECODES_DIR}/erc20/proxy_bytecode.hpp )
add_custom_command(
   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proxy.sol
   OUTPUT ${PROXY_BYTECODE_PATH}
   COMMAND sh compile_command.sh "${CMAKE_CURRENT_SOURCE_DIR}/proxy.sol" "${CMAKE_CURRENT_BINARY_DIR}/proxy_config.json" "${CMAKE_CURRENT_BINARY_DIR}/proxy_header.hpp" > "${PROXY_BYTECODE_PATH}"
   )


add_custom_target(GenerateErc20Bytecode ALL
   DEPENDS ${BYTECODE_PATH}
   DEPENDS ${PROXY_BYTECODE_PATH}
   )
