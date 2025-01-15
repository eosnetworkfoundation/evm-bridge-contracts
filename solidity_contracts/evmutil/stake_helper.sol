
// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol


// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC-20 standard as defined in the ERC.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/interfaces/IERC20.sol


// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC20.sol)

pragma solidity ^0.8.20;


// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/introspection/IERC165.sol


// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/IERC165.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/interfaces/IERC165.sol


// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC165.sol)

pragma solidity ^0.8.20;


// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/interfaces/IERC1363.sol


// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC1363.sol)

pragma solidity ^0.8.20;



/**
 * @title IERC1363
 * @dev Interface of the ERC-1363 standard as defined in the https://eips.ethereum.org/EIPS/eip-1363[ERC-1363].
 *
 * Defines an extension interface for ERC-20 tokens that supports executing code on a recipient contract
 * after `transfer` or `transferFrom`, or code on a spender contract after `approve`, in a single transaction.
 */
interface IERC1363 is IERC20, IERC165 {
    /*
     * Note: the ERC-165 identifier for this interface is 0xb0202a11.
     * 0xb0202a11 ===
     *   bytes4(keccak256('transferAndCall(address,uint256)')) ^
     *   bytes4(keccak256('transferAndCall(address,uint256,bytes)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256,bytes)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256,bytes)'))
     */

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(address to, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(address to, uint256 value, bytes calldata data) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(address from, address to, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(address from, address to, uint256 value, bytes calldata data) external returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(address spender, uint256 value) external returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @param data Additional data with no specified format, sent in call to `spender`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(address spender, uint256 value, bytes calldata data) external returns (bool);
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Errors.sol



pragma solidity ^0.8.20;

/**
 * @dev Collection of common custom errors used in multiple contracts
 *
 * IMPORTANT: Backwards compatibility is not guaranteed in future versions of the library.
 * It is recommended to avoid relying on the error API for critical functionality.
 */
library Errors {
    /**
     * @dev The ETH balance of the account is not enough to perform the operation.
     */
    error InsufficientBalance(uint256 balance, uint256 needed);

    /**
     * @dev A call to an address target failed. The target may have reverted.
     */
    error FailedCall();

    /**
     * @dev The deployment failed.
     */
    error FailedDeployment();
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Address.sol


// OpenZeppelin Contracts (last updated v5.0.0) (utils/Address.sol)

pragma solidity ^0.8.20;


/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev There's no code at `target` (it is not a contract).
     */
    error AddressEmptyCode(address target);

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.8.20/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        if (address(this).balance < amount) {
            revert Errors.InsufficientBalance(address(this).balance, amount);
        }

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert Errors.FailedCall();
        }
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason or custom error, it is bubbled
     * up by this function (like regular Solidity function calls). However, if
     * the call reverted with no returned reason, this function reverts with a
     * {Errors.FailedCall} error.
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        if (address(this).balance < value) {
            revert Errors.InsufficientBalance(address(this).balance, value);
        }
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and reverts if the target
     * was not a contract or bubbling up the revert reason (falling back to {Errors.FailedCall}) in case
     * of an unsuccessful call.
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata
    ) internal view returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            // only check if target is a contract if the call was successful and the return data is empty
            // otherwise we already know that it was a contract
            if (returndata.length == 0 && target.code.length == 0) {
                revert AddressEmptyCode(target);
            }
            return returndata;
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and reverts if it wasn't, either by bubbling the
     * revert reason or with a default {Errors.FailedCall} error.
     */
    function verifyCallResult(bool success, bytes memory returndata) internal pure returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            return returndata;
        }
    }

    /**
     * @dev Reverts with returndata if present. Otherwise reverts with {Errors.FailedCall}.
     */
    function _revert(bytes memory returndata) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            /// @solidity memory-safe-assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert Errors.FailedCall();
        }
    }
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol


// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.20;




/**
 * @title SafeERC20
 * @dev Wrappers around ERC-20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using Address for address;

    /**
     * @dev An operation with an ERC-20 token failed.
     */
    error SafeERC20FailedOperation(address token);

    /**
     * @dev Indicates a failed `decreaseAllowance` request.
     */
    error SafeERC20FailedDecreaseAllowance(address spender, uint256 currentAllowance, uint256 requestedDecrease);

    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    /**
     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        forceApprove(token, spender, oldAllowance + value);
    }

    /**
     * @dev Decrease the calling contract's allowance toward `spender` by `requestedDecrease`. If `token` returns no
     * value, non-reverting calls are assumed to be successful.
     */
    function safeDecreaseAllowance(IERC20 token, address spender, uint256 requestedDecrease) internal {
        unchecked {
            uint256 currentAllowance = token.allowance(address(this), spender);
            if (currentAllowance < requestedDecrease) {
                revert SafeERC20FailedDecreaseAllowance(spender, currentAllowance, requestedDecrease);
            }
            forceApprove(token, spender, currentAllowance - requestedDecrease);
        }
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     */
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeCall(token.approve, (spender, value));

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(token, abi.encodeCall(token.approve, (spender, 0)));
            _callOptionalReturn(token, approvalCall);
        }
    }

    /**
     * @dev Performs an {ERC1363} transferAndCall, with a fallback to the simple {ERC20} transfer if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferAndCallRelaxed(IERC1363 token, address to, uint256 value, bytes memory data) internal {
        if (to.code.length == 0) {
            safeTransfer(token, to, value);
        } else if (!token.transferAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} transferFromAndCall, with a fallback to the simple {ERC20} transferFrom if the target
     * has no code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferFromAndCallRelaxed(
        IERC1363 token,
        address from,
        address to,
        uint256 value,
        bytes memory data
    ) internal {
        if (to.code.length == 0) {
            safeTransferFrom(token, from, to, value);
        } else if (!token.transferFromAndCall(from, to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} approveAndCall, with a fallback to the simple {ERC20} approve if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * NOTE: When the recipient address (`to`) has no code (i.e. is an EOA), this function behaves as {forceApprove}.
     * Opposedly, when the recipient address (`to`) has code, this function only attempts to call {ERC1363-approveAndCall}
     * once without retrying, and relies on the returned value to be true.
     *
     * Reverts if the returned value is other than `true`.
     */
    function approveAndCallRelaxed(IERC1363 token, address to, uint256 value, bytes memory data) internal {
        if (to.code.length == 0) {
            forceApprove(token, to, value);
        } else if (!token.approveAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address-functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        bytes memory returndata = address(token).functionCall(data);
        if (returndata.length != 0 && !abi.decode(returndata, (bool))) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturn} that silents catches all reverts and returns a bool instead.
     */
    function _callOptionalReturnBool(IERC20 token, bytes memory data) private returns (bool) {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We cannot use {Address-functionCall} here since this should return false
        // and not revert is the subcall reverts.

        (bool success, bytes memory returndata) = address(token).call(data);
        return success && (returndata.length == 0 || abi.decode(returndata, (bool))) && address(token).code.length > 0;
    }
}

// File: @openzeppelin/contracts/interfaces/draft-IERC1822.sol


// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/draft-IERC1822.sol)

pragma solidity ^0.8.20;

/**
 * @dev ERC1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified
 * proxy whose upgrades are fully controlled by the current implementation.
 */
interface IERC1822Proxiable {
    /**
     * @dev Returns the storage slot that the proxiable contract assumes is being used to store the implementation
     * address.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy.
     */
    function proxiableUUID() external view returns (bytes32);
}

// File: @openzeppelin/contracts/proxy/beacon/IBeacon.sol


// OpenZeppelin Contracts (last updated v5.0.0) (proxy/beacon/IBeacon.sol)

pragma solidity ^0.8.20;

/**
 * @dev This is the interface that {BeaconProxy} expects of its beacon.
 */
interface IBeacon {
    /**
     * @dev Must return an address that can be used as a delegate call target.
     *
     * {UpgradeableBeacon} will check that this address is a contract.
     */
    function implementation() external view returns (address);
}

// File: @openzeppelin/contracts/utils/StorageSlot.sol


// OpenZeppelin Contracts (last updated v5.0.0) (utils/StorageSlot.sol)
// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.

pragma solidity ^0.8.20;

/**
 * @dev Library for reading and writing primitive types to specific storage slots.
 *
 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.
 * This library helps with reading and writing to such slots without the need for inline assembly.
 *
 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.
 *
 * Example usage to set ERC1967 implementation slot:
 * ```solidity
 * contract ERC1967 {
 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 *
 *     function _getImplementation() internal view returns (address) {
 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
 *     }
 *
 *     function _setImplementation(address newImplementation) internal {
 *         require(newImplementation.code.length > 0);
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 */
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    struct StringSlot {
        string value;
    }

    struct BytesSlot {
        bytes value;
    }

    /**
     * @dev Returns an `AddressSlot` with member `value` located at `slot`.
     */
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BooleanSlot` with member `value` located at `slot`.
     */
    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Bytes32Slot` with member `value` located at `slot`.
     */
    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Uint256Slot` with member `value` located at `slot`.
     */
    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` with member `value` located at `slot`.
     */
    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.
     */
    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := store.slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` with member `value` located at `slot`.
     */
    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.
     */
    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := store.slot
        }
    }
}

// File: @openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol


// OpenZeppelin Contracts (last updated v5.0.0) (proxy/ERC1967/ERC1967Utils.sol)

pragma solidity ^0.8.20;




/**
 * @dev This abstract contract provides getters and event emitting update functions for
 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967] slots.
 */
library ERC1967Utils {
    // We re-declare ERC-1967 events here because they can't be used directly from IERC1967.
    // This will be fixed in Solidity 0.8.21. At that point we should remove these events.
    /**
     * @dev Emitted when the implementation is upgraded.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Emitted when the admin account has changed.
     */
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
     * @dev Emitted when the beacon is changed.
     */
    event BeaconUpgraded(address indexed beacon);

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev The `implementation` of the proxy is invalid.
     */
    error ERC1967InvalidImplementation(address implementation);

    /**
     * @dev The `admin` of the proxy is invalid.
     */
    error ERC1967InvalidAdmin(address admin);

    /**
     * @dev The `beacon` of the proxy is invalid.
     */
    error ERC1967InvalidBeacon(address beacon);

    /**
     * @dev An upgrade function sees `msg.value > 0` that may be lost.
     */
    error ERC1967NonPayable();

    /**
     * @dev Returns the current implementation address.
     */
    function getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        if (newImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(newImplementation);
        }
        StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /**
     * @dev Performs implementation upgrade with additional setup call if data is nonempty.
     * This function is payable only if the setup call is performed, otherwise `msg.value` is rejected
     * to avoid stuck value in the contract.
     *
     * Emits an {IERC1967-Upgraded} event.
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);

        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        } else {
            _checkNonPayable();
        }
    }

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Returns the current admin.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by EIP1967) using
     * the https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`
     */
    function getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(ADMIN_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 admin slot.
     */
    function _setAdmin(address newAdmin) private {
        if (newAdmin == address(0)) {
            revert ERC1967InvalidAdmin(address(0));
        }
        StorageSlot.getAddressSlot(ADMIN_SLOT).value = newAdmin;
    }

    /**
     * @dev Changes the admin of the proxy.
     *
     * Emits an {IERC1967-AdminChanged} event.
     */
    function changeAdmin(address newAdmin) internal {
        emit AdminChanged(getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is the keccak-256 hash of "eip1967.proxy.beacon" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Returns the current beacon.
     */
    function getBeacon() internal view returns (address) {
        return StorageSlot.getAddressSlot(BEACON_SLOT).value;
    }

    /**
     * @dev Stores a new beacon in the EIP1967 beacon slot.
     */
    function _setBeacon(address newBeacon) private {
        if (newBeacon.code.length == 0) {
            revert ERC1967InvalidBeacon(newBeacon);
        }

        StorageSlot.getAddressSlot(BEACON_SLOT).value = newBeacon;

        address beaconImplementation = IBeacon(newBeacon).implementation();
        if (beaconImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(beaconImplementation);
        }
    }

    /**
     * @dev Change the beacon and trigger a setup call if data is nonempty.
     * This function is payable only if the setup call is performed, otherwise `msg.value` is rejected
     * to avoid stuck value in the contract.
     *
     * Emits an {IERC1967-BeaconUpgraded} event.
     *
     * CAUTION: Invoking this function has no effect on an instance of {BeaconProxy} since v5, since
     * it uses an immutable beacon without looking at the value of the ERC-1967 beacon slot for
     * efficiency.
     */
    function upgradeBeaconToAndCall(address newBeacon, bytes memory data) internal {
        _setBeacon(newBeacon);
        emit BeaconUpgraded(newBeacon);

        if (data.length > 0) {
            Address.functionDelegateCall(IBeacon(newBeacon).implementation(), data);
        } else {
            _checkNonPayable();
        }
    }

    /**
     * @dev Reverts if `msg.value` is not zero. It can be used to avoid `msg.value` stuck in the contract
     * if an upgrade doesn't perform an initialization call.
     */
    function _checkNonPayable() private {
        if (msg.value > 0) {
            revert ERC1967NonPayable();
        }
    }
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/proxy/utils/Initializable.sol


// OpenZeppelin Contracts (last updated v5.0.0) (proxy/utils/Initializable.sol)

pragma solidity ^0.8.20;

/**
 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed
 * behind a proxy. Since proxied contracts do not make use of a constructor, it's common to move constructor logic to an
 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer
 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.
 *
 * The initialization functions use a version number. Once a version number is used, it is consumed and cannot be
 * reused. This mechanism prevents re-execution of each "step" but allows the creation of new initialization steps in
 * case an upgrade adds a module that needs to be initialized.
 *
 * For example:
 *
 * [.hljs-theme-light.nopadding]
 * ```solidity
 * contract MyToken is ERC20Upgradeable {
 *     function initialize() initializer public {
 *         __ERC20_init("MyToken", "MTK");
 *     }
 * }
 *
 * contract MyTokenV2 is MyToken, ERC20PermitUpgradeable {
 *     function initializeV2() reinitializer(2) public {
 *         __ERC20Permit_init("MyToken");
 *     }
 * }
 * ```
 *
 * TIP: To avoid leaving the proxy in an uninitialized state, the initializer function should be called as early as
 * possible by providing the encoded function call as the `_data` argument to {ERC1967Proxy-constructor}.
 *
 * CAUTION: When used with inheritance, manual care must be taken to not invoke a parent initializer twice, or to ensure
 * that all initializers are idempotent. This is not verified automatically as constructors are by Solidity.
 *
 * [CAUTION]
 * ====
 * Avoid leaving a contract uninitialized.
 *
 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation
 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke
 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:
 *
 * [.hljs-theme-light.nopadding]
 * ```
 * /// @custom:oz-upgrades-unsafe-allow constructor
 * constructor() {
 *     _disableInitializers();
 * }
 * ```
 * ====
 */
abstract contract Initializable {
    /**
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:openzeppelin.storage.Initializable
     */
    struct InitializableStorage {
        /**
         * @dev Indicates that the contract has been initialized.
         */
        uint64 _initialized;
        /**
         * @dev Indicates that the contract is in the process of being initialized.
         */
        bool _initializing;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /**
     * @dev The contract is already initialized.
     */
    error InvalidInitialization();

    /**
     * @dev The contract is not initializing.
     */
    error NotInitializing();

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint64 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that in the context of a constructor an `initializer` may be invoked any
     * number of times. This behavior in the constructor can be useful during testing and is not expected to be used in
     * production.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no previous version was
        //                 initialized
        // - construction: the contract is initialized at version 1 (no reininitialization) and the
        //                 current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: Setting the version to 2**64 - 1 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint64 version) {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    /**
     * @dev Reverts if the contract is not in an initializing state. See {onlyInitializing}.
     */
    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    // solhint-disable-next-line var-name-mixedcase
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        assembly {
            $.slot := INITIALIZABLE_STORAGE
        }
    }
}

// File: https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/proxy/utils/UUPSUpgradeable.sol


// OpenZeppelin Contracts (last updated v5.0.0) (proxy/utils/UUPSUpgradeable.sol)

pragma solidity ^0.8.20;




/**
 * @dev An upgradeability mechanism designed for UUPS proxies. The functions included here can perform an upgrade of an
 * {ERC1967Proxy}, when this contract is set as the implementation behind such a proxy.
 *
 * A security mechanism ensures that an upgrade does not turn off upgradeability accidentally, although this risk is
 * reinstated if the upgrade retains upgradeability but removes the security mechanism, e.g. by replacing
 * `UUPSUpgradeable` with a custom implementation of upgrades.
 *
 * The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
 */
abstract contract UUPSUpgradeable is Initializable, IERC1822Proxiable {
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address private immutable __self = address(this);

    /**
     * @dev The version of the upgrade interface of the contract. If this getter is missing, both `upgradeTo(address)`
     * and `upgradeToAndCall(address,bytes)` are present, and `upgradeTo` must be used if no function should be called,
     * while `upgradeToAndCall` will invoke the `receive` function if the second argument is the empty byte string.
     * If the getter returns `"5.0.0"`, only `upgradeToAndCall(address,bytes)` is present, and the second argument must
     * be the empty byte string if no function should be called, making it impossible to invoke the `receive` function
     * during an upgrade.
     */
    string public constant UPGRADE_INTERFACE_VERSION = "5.0.0";

    /**
     * @dev The call is from an unauthorized context.
     */
    error UUPSUnauthorizedCallContext();

    /**
     * @dev The storage `slot` is unsupported as a UUID.
     */
    error UUPSUnsupportedProxiableUUID(bytes32 slot);

    /**
     * @dev Check that the execution is being performed through a delegatecall call and that the execution context is
     * a proxy contract with an implementation (as defined in ERC-1967) pointing to self. This should only be the case
     * for UUPS and transparent proxies that are using the current contract as their implementation. Execution of a
     * function through ERC-1167 minimal proxies (clones) would not normally pass this test, but is not guaranteed to
     * fail.
     */
    modifier onlyProxy() {
        _checkProxy();
        _;
    }

    /**
     * @dev Check that the execution is not being performed through a delegate call. This allows a function to be
     * callable on the implementing contract but not through proxies.
     */
    modifier notDelegated() {
        _checkNotDelegated();
        _;
    }

    function __UUPSUpgradeable_init() internal onlyInitializing {
    }

    function __UUPSUpgradeable_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev Implementation of the ERC-1822 {proxiableUUID} function. This returns the storage slot used by the
     * implementation. It is used to validate the implementation's compatibility when performing an upgrade.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy. This is guaranteed by the `notDelegated` modifier.
     */
    function proxiableUUID() external view virtual notDelegated returns (bytes32) {
        return ERC1967Utils.IMPLEMENTATION_SLOT;
    }

    /**
     * @dev Upgrade the implementation of the proxy to `newImplementation`, and subsequently execute the function call
     * encoded in `data`.
     *
     * Calls {_authorizeUpgrade}.
     *
     * Emits an {Upgraded} event.
     *
     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data);
    }

    /**
     * @dev Reverts if the execution is not performed via delegatecall or the execution
     * context is not of a proxy with an ERC-1967 compliant implementation pointing to self.
     * See {_onlyProxy}.
     */
    function _checkProxy() internal view virtual {
        if (
            address(this) == __self || // Must be called through delegatecall
            ERC1967Utils.getImplementation() != __self // Must be called through an active proxy
        ) {
            revert UUPSUnauthorizedCallContext();
        }
    }

    /**
     * @dev Reverts if the execution is performed via delegatecall.
     * See {notDelegated}.
     */
    function _checkNotDelegated() internal view virtual {
        if (address(this) != __self) {
            // Must not be called through delegatecall
            revert UUPSUnauthorizedCallContext();
        }
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
     * {upgradeToAndCall}.
     *
     * Normally, this function will use an xref:access.adoc[access control] modifier such as {Ownable-onlyOwner}.
     *
     * ```solidity
     * function _authorizeUpgrade(address) internal onlyOwner {}
     * ```
     */
    function _authorizeUpgrade(address newImplementation) internal virtual;

    /**
     * @dev Performs an implementation upgrade with a security check for UUPS proxies, and additional setup call.
     *
     * As a security check, {proxiableUUID} is invoked in the new implementation, and the return value
     * is expected to be the implementation slot in ERC-1967.
     *
     * Emits an {IERC1967-Upgraded} event.
     */
    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data) private {
        try IERC1822Proxiable(newImplementation).proxiableUUID() returns (bytes32 slot) {
            if (slot != ERC1967Utils.IMPLEMENTATION_SLOT) {
                revert UUPSUnsupportedProxiableUUID(slot);
            }
            ERC1967Utils.upgradeToAndCall(newImplementation, data);
        } catch {
            // The implementation is not UUPS
            revert ERC1967Utils.ERC1967InvalidImplementation(newImplementation);
        }
    }
}

// File: contracts/stakehelper.sol
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.18;

contract StakeHelper is Initializable, UUPSUpgradeable {

    using SafeERC20 for IERC20;

    string  public linkedEOSAccountName;
    address public linkedEOSAddress;
    address public evmAddress;
    uint256 public depositFee;
    uint256 public lockTime;
    uint256 public maxPendingQueueSize;

    IERC20 public linkedERC20;

    struct PendingFunds {
        uint256 amount;
        uint256 startingHeight;
    }

    struct StakeInfo {
        uint256 amount;
        uint256 pendingFundsFirst;
        uint256 pendingFundsLast;
        uint256 unlockedFund;
        mapping(uint256 => PendingFunds) pendingFunds;
    }

    event Deposit(address indexed caller, address indexed to, uint256 value);
    event Withdraw(address indexed caller, address indexed from, uint256 value);
    event Restake(address indexed caller, address indexed from, address indexed to, uint256 value);

    mapping(address => mapping(address => StakeInfo)) public stakeInfo;

    mapping(address => mapping(uint256 => address)) public userPendingTracker;

    struct TransferAuthorization {
        uint256 amount;
        address target;
        bool exists;
    }

    mapping(address => mapping(address => TransferAuthorization)) public transferAuthorizations;
    mapping(address => address[]) private transferAuthorizationsOperators;

    event AuthorizeTransfer(address indexed caller, address indexed operator, address indexed validator, uint256 amount);
    event PerformTransfer(address indexed user, address indexed operator, address indexed fromValidator, address toValidator, uint256 amount);
    event ReDelegatePendingFunds(address indexed caller, address indexed validator, uint256 amount);
    event FundsClaimed(address indexed caller, address indexed validator, uint256 amount, bool isBTC);

    function initialize(address _linkedEOSAddress, address _evmAddress, IERC20 _linkedERC20, uint256 _depositFee) initializer public {
        __UUPSUpgradeable_init();

        linkedERC20 = _linkedERC20;
        evmAddress = _evmAddress;
        linkedEOSAddress = _linkedEOSAddress;
        linkedEOSAccountName = _addressToName(linkedEOSAddress);
        depositFee = _depositFee;
        lockTime = 2419200; // 28 days
        maxPendingQueueSize = 50; // A limit that normally will not be hit. Sort of last defence.
    }

    function _addressToName(address input ) internal pure returns (string memory) {
        require(_isReservedAddress(input));
        uint64 a = uint64(uint160(input));
        bytes memory bstr = new bytes(12);

        uint count = 0;
        for (uint i = 0; i < 12 ; i++) {
            uint64 c = (a >> (64 - 5*(i+1))) & uint64(31);
            if (c == 0) {
                bstr[i] = bytes1(uint8(46)); // .
            }
            else if (c <= 5) {
                bstr[i] = bytes1(uint8(c + 48)); // '0' + b
                count = i + 1;
            }
            else {
                bstr[i] = bytes1(uint8(c - 6 + 97)); // 'a' + b - 6
                count = i + 1;
            }
        }

        bytes memory bstrTrimmed = new bytes(count);
        for (uint j = 0; j < count; j++) {
            bstrTrimmed[j] = bstr[j];
        }
        return string(bstrTrimmed);
    }

    function _authorizeUpgrade(address) internal virtual override {
        if (msg.sender != linkedEOSAddress) { revert(); }
    }

    function _isReservedAddress(address addr) internal pure returns (bool) {
        return ((uint160(addr) & uint160(0xFffFfFffffFfFFffffFFFffF0000000000000000)) == uint160(0xBBbbBbBbbBbbBbbbBbbbBBbb0000000000000000));
    }

    receive() external payable {
        require(msg.sender == address(linkedERC20),"Only XBTC contract can send funds to this contract");
    }

    function refreshPendingFunds(address _target, address _caller) internal {
        StakeInfo storage stake = stakeInfo[_target][_caller];
        while (stake.pendingFundsFirst < stake.pendingFundsLast) {
            PendingFunds storage firstEntry = stake.pendingFunds[stake.pendingFundsFirst];
            if (firstEntry.startingHeight + lockTime <= block.number) {
                stake.unlockedFund += firstEntry.amount;
                delete stake.pendingFunds[stake.pendingFundsFirst];
                stake.pendingFundsFirst += 1;
            }
            else {
                break;
            }
        }
    }

    function pushPendingFunds(address _target, address _caller, uint256 _amount) internal {
        refreshPendingFunds(_target, _caller);
        StakeInfo storage stake = stakeInfo[_target][_caller];

        if (stake.pendingFundsLast - stake.pendingFundsFirst < maxPendingQueueSize) {
            PendingFunds storage newEntry = stake.pendingFunds[stake.pendingFundsLast];
            newEntry.amount = _amount;
            newEntry.startingHeight = block.number;
            stake.pendingFundsLast += 1;
        }
        else {
            // Merge into last one
            PendingFunds storage lastEntry = stake.pendingFunds[stake.pendingFundsLast - 1];
            lastEntry.startingHeight = block.number;
            lastEntry.amount += _amount;
        }
    }

    function markUserPendingFund(address _target, address _user) internal {
        // Note: In exsat, storage is usually more expensive then CPU so we simply loop here.
        // The user should have only limited unclaimed fund in different validators so it should be fine.
        // We can consider improve this logic if it turns out to be too slow.
        uint i = 0;
        while (true)  {
            if (userPendingTracker[_user][i] == _target) {
                break;
            }
            if (userPendingTracker[_user][i] == address(0)) {
                userPendingTracker[_user][i] = _target;
                break;
            }
            i++;
        }
    }

    function unmarkUserPendingFund(address _target, address _user) internal {
        // Note: In exsat, storage is usually more expensive then CPU so we simply loop here.
        // The user should have only limited unclaimed fund in different validators so it should be fine.
        // We can consider improve this logic if it turns out to be too slow.
        uint i = 0;
        uint target = 0;
        bool found = false;
        while (true)  {
            if (userPendingTracker[_user][i] == address(0)) {
                if (!found) {
                    break;
                } else {
                    assert(i > 0);
                    // It's fine for target = i-1 case.
                    userPendingTracker[_user][target] = userPendingTracker[_user][i-1];
                    userPendingTracker[_user][i-1] = address(0);
                }
                break;
            }
            if (userPendingTracker[_user][i] == _target) {
                found = true;
                target = i;
            }
            i++;
        }
    }

    function setFee(uint256 _depositFee) public {
        require(msg.sender == linkedEOSAddress, "Bridge: only linked EOS address can set fee");
        depositFee = _depositFee;
    }

    function setLockTime(uint256 _lockTime) public {
        require(msg.sender == linkedEOSAddress, "Bridge: only linked EOS address can set lock time");
        lockTime = _lockTime;
    }

    function deposit(address _target, uint256 _amount) public payable {
        StakeInfo storage stake = stakeInfo[_target][msg.sender];
        require(msg.value == depositFee, "Deposit: must pay exact amount of deposit fee");
        if (_amount > 0) {
            linkedERC20.safeTransferFrom(address(msg.sender), address(this), _amount);
            stake.amount = stake.amount + _amount;
        }

        // The action is aynchronously viewed from EVM and looks UNSAFE.
        // BUT in fact the call will be executed as inline action.
        // If the cross chain call fail, the whole tx including the EVM action will be rejected.
        bytes memory receiver_msg = abi.encodeWithSignature("deposit(address,uint256,address)", _target, _amount, msg.sender);
        (bool success, ) = evmAddress.call(abi.encodeWithSignature("bridgeMsgV0(string,bool,bytes)", linkedEOSAccountName, true, receiver_msg ));
        if(!success) { revert(); }

        emit Deposit(msg.sender, _target, _amount);
    }

    function restake(address _from, address _to, uint256 _amount) external {
        StakeInfo storage stakeFrom = stakeInfo[_from][msg.sender];

        require(_amount <= stakeFrom.amount, "Restake: cannot restake more than deposited amound");

        StakeInfo storage stakeTo = stakeInfo[_to][msg.sender];

        if (_amount > 0) {
            stakeFrom.amount = stakeFrom.amount - _amount;
            stakeTo.amount = stakeTo.amount + _amount;
        }

        // The action is aynchronously viewed from EVM and looks UNSAFE.
        // BUT in fact the call will be executed as inline action.
        // If the cross chain call fail, the whole tx including the EVM action will be rejected.
        bytes memory receiver_msg = abi.encodeWithSignature("restake(address,address,uint256,address)", _from, _to, _amount, msg.sender);
        (bool success, ) = evmAddress.call(abi.encodeWithSignature("bridgeMsgV0(string,bool,bytes)", linkedEOSAccountName, true, receiver_msg ));
        if(!success) { revert(); }

        emit Restake(msg.sender, _from, _to, _amount);
    }

    function claim(address _target) external {
        // The action is aynchronously viewed from EVM and looks UNSAFE.
        // BUT in fact the call will be executed as inline action.
        // If the cross chain call fail, the whole tx including the EVM action will be rejected.
        bytes memory receiver_msg = abi.encodeWithSignature("claim(address,address)", _target, msg.sender);
        (bool success, ) = evmAddress.call(abi.encodeWithSignature("bridgeMsgV0(string,bool,bytes)", linkedEOSAccountName, true, receiver_msg ));
        if(!success) { revert(); }
    }

    function withdraw(address _target, uint256 _amount) external {
        StakeInfo storage stake = stakeInfo[_target][msg.sender];

        require(_amount <= stake.amount, "Withdraw: cannot withdraw more than deposited amound");

        if (_amount > 0) {
            stake.amount = stake.amount - _amount;

            pushPendingFunds(_target, address(msg.sender), _amount);
            markUserPendingFund(_target, address(msg.sender));
        }

        // The action is aynchronously viewed from EVM and looks UNSAFE.
        // BUT in fact the call will be executed as inline action.
        // If the cross chain call fail, the whole tx including the EVM action will be rejected.
        bytes memory receiver_msg = abi.encodeWithSignature("withdraw(address,uint256,address)", _target, _amount, msg.sender);
        (bool success, ) = evmAddress.call(abi.encodeWithSignature("bridgeMsgV0(string,bool,bytes)", linkedEOSAccountName, true, receiver_msg ));
        if(!success) { revert(); }

        emit Withdraw(msg.sender, _target, _amount);
    }

    function pendingFunds(address _target, address _user) external view returns (uint256) {
        StakeInfo storage stake = stakeInfo[_target][_user];
        uint256 result = stake.unlockedFund;
        uint256 first = stake.pendingFundsFirst;
        uint256 last = stake.pendingFundsLast;

        while (first < last) {
            PendingFunds storage firstEntry = stake.pendingFunds[first];
            if (firstEntry.startingHeight + lockTime <= block.number) {
                result += firstEntry.amount;
                first += 1;
            }
            else {
                break;
            }
        }

        return result;
    }

    function pendingFundQueue(address _target, address _user) external view returns (PendingFunds [] memory) {
        StakeInfo storage stake = stakeInfo[_target][_user];
        uint256 first = stake.pendingFundsFirst;
        uint256 last = stake.pendingFundsLast;

        while (first < last) {
            PendingFunds storage firstEntry = stake.pendingFunds[first];
            if (firstEntry.startingHeight + lockTime <= block.number) {
                first += 1;
                continue;
            }
            else {
                break;
            }
        }
        PendingFunds [] memory result = new PendingFunds[](last - first);
        for (uint i = 0; i < last - first; i++) {
            PendingFunds storage entry = stake.pendingFunds[first + i];
            result[i] = entry;
        }
        return result;
    }

    function claimPendingFunds(address _target) external {
        refreshPendingFunds(_target, address(msg.sender));

        StakeInfo storage stake = stakeInfo[_target][msg.sender];
        uint256 funds = stake.unlockedFund;
        if (stake.unlockedFund > 0) {
            stake.unlockedFund = 0;
            linkedERC20.safeTransfer(address(msg.sender), funds);
        }
        if (stake.unlockedFund == 0 && stake.pendingFundsFirst == stake.pendingFundsLast) {
            unmarkUserPendingFund(_target, address(msg.sender));
        }
        emit FundsClaimed(msg.sender, _target, funds, false);
    }

    function claimPendingFunds(address _target, bool receiveAsBTC) external {
        refreshPendingFunds(_target, msg.sender);

        StakeInfo storage stake = stakeInfo[_target][msg.sender];
        uint256 funds = stake.unlockedFund;

        if(funds > 0){
            stake.unlockedFund = 0;
            if (receiveAsBTC) {
                (bool success, bytes memory data) = address(linkedERC20).call(
                    abi.encodeWithSignature("withdraw(uint256)", funds)
                );
                require(success, "Withdraw call failed");
            } else {
                linkedERC20.safeTransfer(msg.sender, funds);
            }
        }

        if (stake.unlockedFund == 0 && stake.pendingFundsFirst == stake.pendingFundsLast) {
            unmarkUserPendingFund(_target, msg.sender);
        }
        if (funds > 0 && receiveAsBTC) {
            payable(msg.sender).transfer(funds);
        }
        emit FundsClaimed(msg.sender, _target, funds, receiveAsBTC);
    }

    function claimPendingFunds() external {
        address _user = address(msg.sender);
        uint i = 0;
        uint256 totalFunds = 0;
        while (true)  {
            if (userPendingTracker[_user][i] == address(0)) {
                break;
            }

            address _target = userPendingTracker[_user][i];

            refreshPendingFunds(_target, address(msg.sender));

            StakeInfo storage stake = stakeInfo[_target][msg.sender];

            if (stake.unlockedFund > 0) {
                uint256 funds = stake.unlockedFund;
                totalFunds += funds;
                stake.unlockedFund = 0;
                linkedERC20.safeTransfer(address(msg.sender), funds);
            }
            if (stake.unlockedFund == 0 && stake.pendingFundsFirst == stake.pendingFundsLast) {
                uint j = i + 1;
                while (true)  {
                    if (userPendingTracker[_user][j] == address(0)) {
                        userPendingTracker[_user][i] = userPendingTracker[_user][j - 1];
                        userPendingTracker[_user][j - 1] = address(0);
                        break;
                    }
                    j++;
                }
                // process same row next round
            }
            else {
                i++;
            }
        }
        emit FundsClaimed(_user, address(0), totalFunds, false);
    }

    function claimPendingFunds(bool receiveAsBTC) external {
        address _user = msg.sender;
        uint256 totalFunds = 0;
        uint i = 0;

        while (true) {
            if (userPendingTracker[_user][i] == address(0)) {
                break;
            }

            address _target = userPendingTracker[_user][i];
            refreshPendingFunds(_target, _user);

            StakeInfo storage stake = stakeInfo[_target][_user];

            if (stake.unlockedFund > 0) {
                totalFunds += stake.unlockedFund;
                stake.unlockedFund = 0;
            }

            if (stake.unlockedFund == 0 && stake.pendingFundsFirst == stake.pendingFundsLast) {
                uint j = i + 1;
                while (true) {
                    if (userPendingTracker[_user][j] == address(0)) {
                        userPendingTracker[_user][i] = userPendingTracker[_user][j - 1];
                        userPendingTracker[_user][j - 1] = address(0);
                        break;
                    }
                    j++;
                }
            } else {
                i++;
            }
        }
        if(totalFunds > 0){
            if (receiveAsBTC) {
                (bool success, bytes memory data) = address(linkedERC20).call(
                    abi.encodeWithSignature("withdraw(uint256)", totalFunds)
                );
                require(success, "Withdraw call failed");
                payable(_user).transfer(totalFunds);
            } else {
                linkedERC20.safeTransfer(_user, totalFunds);
            }
        }
        emit FundsClaimed(_user, address(0), totalFunds, receiveAsBTC);
    }

    function pendingFunds(address _user) external view returns (uint256) {
        uint256 result = 0;

        uint i = 0;
        while (true)  {
            if (userPendingTracker[_user][i] == address(0)) {
                break;
            }
            address _target = userPendingTracker[_user][i];

            StakeInfo storage stake = stakeInfo[_target][_user];
            result += stake.unlockedFund;
            uint256 first = stake.pendingFundsFirst;
            uint256 last = stake.pendingFundsLast;

            while (first < last) {
                PendingFunds storage firstEntry = stake.pendingFunds[first];
                if (firstEntry.startingHeight + lockTime <= block.number) {
                    result += firstEntry.amount;
                    first += 1;
                }
                else {
                    break;
                }
            }
            i++;
        }

        return result;
    }

    function listValidatorsWithPendingFunds(address _user) external view returns (address [] memory) {
        uint count = 0;
        while (true)  {
            if (userPendingTracker[_user][count] == address(0)) {
                break;
            }
            count++;
        }
        address [] memory result = new address[](count);
        for (uint i = 0; i < count; i++) {
            result[i] = userPendingTracker[_user][i];
        }
        return result;
    }

    function collectFee(address payable dest) public {
        require(msg.sender == linkedEOSAddress, "Bridge: only linked EOS address can collect fee");
        (bool success, ) = dest.call{value: address(this).balance}("");
        require(success, "Address: unable to send value, dest may have reverted");
    }

    function depositWithBTC(address _target) external payable {

        require(msg.value > depositFee, "Deposit: amount must be greater than amount of deposit fee");
        uint256 amount = msg.value - depositFee;
        // Record the initial ERC20 balance
        uint256 initialBalance = linkedERC20.balanceOf(address(this));

        // Call the deposit function
        (bool successDeposit,) = address(linkedERC20).call{value: amount}(
            abi.encodeWithSignature("deposit()")
        );
        require(successDeposit, "Deposit call failed");

        // Record the new ERC20 balance
        uint256 newBalance = linkedERC20.balanceOf(address(this));

        // Ensure the balance increase more than the amount sent
        require(newBalance >= initialBalance + amount, "Conversion failed");

        StakeInfo storage stake = stakeInfo[_target][msg.sender];
        stake.amount = stake.amount + amount;

        // The action is aynchronously viewed from EVM and looks UNSAFE.
        // BUT in fact the call will be executed as inline action.
        // If the cross chain call fail, the whole tx including the EVM action will be rejected.
        bytes memory receiver_msg = abi.encodeWithSignature("deposit(address,uint256,address)", _target, amount, msg.sender);
        (bool success, ) = evmAddress.call(abi.encodeWithSignature("bridgeMsgV0(string,bool,bytes)", linkedEOSAccountName, true, receiver_msg ));
        if(!success) { revert(); }

        emit Deposit(msg.sender, _target, amount);
    }


    function reDelegatePendingFunds(address _newTarget) external {
        require(_newTarget != address(0), "Invalid target address");

        address _user = msg.sender;
        uint256 reDelegateAmount = 0;
        uint i = 0;
        while (true) {
            if (userPendingTracker[_user][i] == address(0)) {
                break;
            }

            address _target = userPendingTracker[_user][i];
            StakeInfo storage stake = stakeInfo[_target][_user];
            refreshPendingFunds(_target, _user);

            while (stake.pendingFundsFirst < stake.pendingFundsLast) {
                PendingFunds storage firstEntry = stake.pendingFunds[stake.pendingFundsFirst];
                if (firstEntry.startingHeight + lockTime <= block.number) {
                    stake.unlockedFund += firstEntry.amount;
                    delete stake.pendingFunds[stake.pendingFundsFirst];
                    stake.pendingFundsFirst += 1;
                }
                else {
                    reDelegateAmount += firstEntry.amount;
                    delete stake.pendingFunds[stake.pendingFundsFirst];
                    stake.pendingFundsFirst += 1;
                }
            }


            if (stake.unlockedFund == 0 && stake.pendingFundsFirst == stake.pendingFundsLast) {
                uint j = i + 1;
                while (true) {
                    if (userPendingTracker[_user][j] == address(0)) {
                        userPendingTracker[_user][i] = userPendingTracker[_user][j - 1];
                        userPendingTracker[_user][j - 1] = address(0);
                        break;
                    }
                    j++;
                }
            } else {
                i++;
            }
        }
        if(reDelegateAmount > 0){
            stakeInfo[_newTarget][msg.sender].amount += reDelegateAmount;

            bytes memory receiver_msg = abi.encodeWithSignature("deposit(address,uint256,address)", _newTarget, reDelegateAmount, msg.sender);
            (bool success, ) = evmAddress.call(abi.encodeWithSignature("bridgeMsgV0(string,bool,bytes)", linkedEOSAccountName, true, receiver_msg ));
            require(success, "Bridge call failed");
        }

        emit ReDelegatePendingFunds(msg.sender, _newTarget, reDelegateAmount);
    }

    function authorizeTransfer(address _operator, address _fromValidator, uint256 _amount) external {
        require(_amount > 0, "Approve: amount must be greater than zero");
        StakeInfo storage stake = stakeInfo[_fromValidator][msg.sender];
        require(_amount <= stake.amount, "Approve: insufficient stake");

        transferAuthorizations[msg.sender][_operator] = TransferAuthorization(_amount, _fromValidator,true);
        transferAuthorizationsOperators[msg.sender].push(_operator);

        emit AuthorizeTransfer(msg.sender, _operator, _fromValidator, _amount);
    }

    function performTransfer(address _user, address _fromValidator, address _toValidator, uint256 _amount) external {
        TransferAuthorization storage auth = transferAuthorizations[_user][msg.sender];
        require(auth.exists, "Permit: no authorization found");
        require(auth.amount == _amount, "Permit: amount mismatch");
        require(auth.target == _fromValidator, "Permit: target mismatch");

        StakeInfo storage stake = stakeInfo[auth.target][_user];
        require(auth.amount <= stake.amount, "Permit: insufficient stake");

        // Update the stake info
        stake.amount -= auth.amount;
        stakeInfo[_toValidator][msg.sender].amount += auth.amount;


        bytes memory withdraw_msg = abi.encodeWithSignature("withdraw(address,uint256,address)", _fromValidator, auth.amount, _user);
        (bool wdSuccess, ) = evmAddress.call(abi.encodeWithSignature("bridgeMsgV0(string,bool,bytes)", linkedEOSAccountName, true, withdraw_msg ));
        if(!wdSuccess) { revert(); }
        bytes memory deposit_msg = abi.encodeWithSignature("deposit(address,uint256,address)", _toValidator, auth.amount, msg.sender);
        (bool depositSuccess, ) = evmAddress.call(abi.encodeWithSignature("bridgeMsgV0(string,bool,bytes)", linkedEOSAccountName, true, deposit_msg ));
        if(!depositSuccess) { revert(); }

        delete transferAuthorizations[_user][msg.sender]; // Remove the authorization after execution

        emit PerformTransfer(_user, msg.sender, _fromValidator, _toValidator, _amount);
    }


    function revokeAuthorize() external {
        address[] storage operators = transferAuthorizationsOperators[msg.sender];

        for (uint256 i = 0; i < operators.length; i++) {
            address operator = operators[i];
            delete transferAuthorizations[msg.sender][operator];
        }

        delete transferAuthorizationsOperators[msg.sender];
    }
    function revokeAuthorize(address _operator) external {
        delete transferAuthorizations[msg.sender][_operator];
    }
}