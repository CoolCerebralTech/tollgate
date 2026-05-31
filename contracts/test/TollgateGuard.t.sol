// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {TollgateGuard} from "../src/TollgateGuard.sol";
import {TollgateTypes} from "../src/TollgateTypes.sol";

/**
 * @title  TollgateGuard Test Suite
 * @notice Full coverage of every verification path in TollgateGuard.
 *
 * Strategy:
 *   - A test private key (TEST_NOTARY_KEY) is used to sign tokens.
 *   - The Guard is deployed with the address derived from that key.
 *   - vm.sign(TEST_NOTARY_KEY, digest) produces valid signatures.
 *   - A different key (WRONG_KEY) produces invalid signatures.
 *   - The real Phase 1 key is never used in tests.
 */
contract TollgateGuardTest is Test {

    // ── Test accounts ──────────────────────────────────────────────────────────
    uint256 constant TEST_NOTARY_KEY = 0xA11CE;
    uint256 constant WRONG_KEY       = 0xBAD;

    address testNotary;   // derived from TEST_NOTARY_KEY
    address safeSim;      // simulated Safe address
    address destination;  // valid destination address
    address attacker;     // random EOA

    // ── Contract under test ────────────────────────────────────────────────────
    TollgateGuard guard;

    // ── EIP-712 type hash (must match TollgateTypes exactly) ──────────────────
    bytes32 constant APPROVAL_TOKEN_TYPEHASH = keccak256(
        "ApprovalToken(bytes32 tokenId,string agentId,address destination,uint256 amountRaw,uint256 chainId,bytes32 nonce,uint256 expiresAt,bytes32 policyHash)"
    );
    bytes32 constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    // ── Default valid token fields ─────────────────────────────────────────────
    bytes32 defaultTokenId;
    bytes32 defaultNonce;
    bytes32 defaultPolicyHash;
    string  defaultAgentId;
    uint256 defaultAmountRaw;
    uint256 defaultExpiresAt;

    function setUp() public {
        // Derive the test notary address from the test key.
        testNotary  = vm.addr(TEST_NOTARY_KEY);
        safeSim     = makeAddr("safe");
        destination = makeAddr("destination");
        attacker    = makeAddr("attacker");

        // Deploy the Guard with our test notary and safe addresses.
        vm.prank(safeSim);
        guard = new TollgateGuard(testNotary, safeSim);

        // Default token fields used across multiple tests.
        defaultTokenId   = keccak256("token-id-001");
        defaultNonce     = keccak256("nonce-001");
        defaultPolicyHash = keccak256("policy-hash-v1");
        defaultAgentId   = "trading-bot-01";
        defaultAmountRaw = 1 ether;
        defaultExpiresAt = block.timestamp + 60; // 60 seconds from now
    }

    // ══════════════════════════════════════════════════════════════════════════
    // DEPLOYMENT TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_deployment_setsNotaryAddress() public view {
        assertEq(guard.notaryAddress(), testNotary);
    }

    function test_deployment_setsSafeAddress() public view {
        assertEq(guard.safeAddress(), safeSim);
    }

    function test_deployment_notPaused() public view {
        assertFalse(guard.paused());
    }

    function test_deployment_ownerIsSafe() public view {
        assertEq(guard.owner(), safeSim);
    }

    function test_deployment_rejectsZeroNotary() public {
        vm.expectRevert(TollgateGuard.ZeroAddress.selector);
        new TollgateGuard(address(0), safeSim);
    }

    function test_deployment_rejectsZeroSafe() public {
        vm.expectRevert(TollgateGuard.ZeroAddress.selector);
        new TollgateGuard(testNotary, address(0));
    }

    function test_deployment_supportsIGuardInterface() public view {
        assertTrue(guard.supportsInterface(0xe6d7a83a));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // APPROVAL TESTS — valid token passes all checks
    // ══════════════════════════════════════════════════════════════════════════

    function test_approve_validToken() public {
        bytes memory data = _buildTokenData(
            defaultTokenId,
            defaultAgentId,
            destination,
            defaultAmountRaw,
            block.chainid,
            defaultNonce,
            defaultExpiresAt,
            defaultPolicyHash,
            TEST_NOTARY_KEY
        );

        // Expect the TransactionApproved event.
        vm.expectEmit(true, true, false, false);
        emit TollgateGuard.TransactionApproved(
            defaultTokenId,
            destination,
            defaultAmountRaw,
            defaultAgentId,
            defaultPolicyHash
        );

        // Call from the Safe — must not revert.
        vm.prank(safeSim);
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
    }

    function test_approve_nonceConsumedAfterExecution() public {
        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination,
            defaultAmountRaw, block.chainid, defaultNonce,
            defaultExpiresAt, defaultPolicyHash, TEST_NOTARY_KEY
        );

        vm.startPrank(safeSim);
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
        guard.checkAfterExecution(bytes32(0), true);
        vm.stopPrank();

        assertTrue(guard.isNonceConsumed(defaultNonce));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // REJECTION TESTS — every invalid path must revert
    // ══════════════════════════════════════════════════════════════════════════

    function test_reject_noToken() public {
        // Empty data — no prefix.
        vm.prank(safeSim);
        vm.expectRevert(TollgateGuard.TokenMissing.selector);
        guard.checkTransaction(
            destination, defaultAmountRaw, "",
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
    }

    function test_reject_expiredToken() public {
        // expiresAt is in the past.
        uint256 expiredAt = block.timestamp - 1;
        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination,
            defaultAmountRaw, block.chainid, defaultNonce,
            expiredAt, defaultPolicyHash, TEST_NOTARY_KEY
        );

        vm.prank(safeSim);
        vm.expectRevert(TollgateGuard.TokenExpired.selector);
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
    }

    function test_reject_replayedNonce() public {
        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination,
            defaultAmountRaw, block.chainid, defaultNonce,
            defaultExpiresAt, defaultPolicyHash, TEST_NOTARY_KEY
        );

        vm.startPrank(safeSim);
        // First use — succeeds.
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
        guard.checkAfterExecution(bytes32(0), true);

        // Second use — same nonce, must revert.
        vm.expectRevert(TollgateGuard.TokenNonceReplayed.selector);
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
        vm.stopPrank();
    }

    function test_reject_wrongSignature() public {
        // Signed with WRONG_KEY — not the notary.
        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination,
            defaultAmountRaw, block.chainid, defaultNonce,
            defaultExpiresAt, defaultPolicyHash, WRONG_KEY
        );

        vm.prank(safeSim);
        vm.expectRevert(TollgateGuard.SignatureInvalid.selector);
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
    }

    function test_reject_tamperedSignature() public {
        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination,
            defaultAmountRaw, block.chainid, defaultNonce,
            defaultExpiresAt, defaultPolicyHash, TEST_NOTARY_KEY
        );

        // Flip the last byte of the signature inside the encoded data.
        data[data.length - 32] = data[data.length - 32] ^ 0xFF;

        vm.prank(safeSim);
        vm.expectRevert(); // SignatureInvalid or abi.decode revert
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
    }

    function test_reject_destinationMismatch() public {
        address wrongDest = makeAddr("wrongDest");
        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination, // token says destination
            defaultAmountRaw, block.chainid, defaultNonce,
            defaultExpiresAt, defaultPolicyHash, TEST_NOTARY_KEY
        );

        vm.prank(safeSim);
        vm.expectRevert(TollgateGuard.DestinationMismatch.selector);
        guard.checkTransaction(
            wrongDest, defaultAmountRaw, data, // but actual to = wrongDest
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
    }

    function test_reject_amountMismatch() public {
        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination,
            defaultAmountRaw, block.chainid, defaultNonce, // token says 1 ether
            defaultExpiresAt, defaultPolicyHash, TEST_NOTARY_KEY
        );

        vm.prank(safeSim);
        vm.expectRevert(TollgateGuard.AmountMismatch.selector);
        guard.checkTransaction(
            destination, 2 ether, data, // actual value = 2 ether
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
    }

    function test_reject_wrongChainId() public {
        // Token signed for chain 1 (mainnet) — Guard is on chain 31337 (anvil).
        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination,
            defaultAmountRaw, 1, defaultNonce, // chainId = 1
            defaultExpiresAt, defaultPolicyHash, TEST_NOTARY_KEY
        );

        vm.prank(safeSim);
        vm.expectRevert(TollgateGuard.ChainIdMismatch.selector);
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
    }

    function test_reject_whenPaused() public {
        // Pause the guard (called by owner = safeSim).
        vm.prank(safeSim);
        guard.setPaused(true);
        assertTrue(guard.paused());

        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination,
            defaultAmountRaw, block.chainid, defaultNonce,
            defaultExpiresAt, defaultPolicyHash, TEST_NOTARY_KEY
        );

        // Even a valid token is blocked when paused.
        vm.prank(safeSim);
        vm.expectRevert(TollgateGuard.GuardIsPaused.selector);
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", safeSim
        );
    }

    function test_reject_callerNotSafe() public {
        bytes memory data = _buildTokenData(
            defaultTokenId, defaultAgentId, destination,
            defaultAmountRaw, block.chainid, defaultNonce,
            defaultExpiresAt, defaultPolicyHash, TEST_NOTARY_KEY
        );

        // Called by attacker, not the Safe.
        vm.prank(attacker);
        vm.expectRevert(TollgateGuard.OnlySafe.selector);
        guard.checkTransaction(
            destination, defaultAmountRaw, data,
            0, 0, 0, 0, address(0), payable(address(0)), "", attacker
        );
    }

    // ══════════════════════════════════════════════════════════════════════════
    // ADMIN TESTS
    // ══════════════════════════════════════════════════════════════════════════

    function test_admin_ownerCanPause() public {
        vm.prank(safeSim);
        guard.setPaused(true);
        assertTrue(guard.paused());

        vm.prank(safeSim);
        guard.setPaused(false);
        assertFalse(guard.paused());
    }

    function test_admin_nonOwnerCannotPause() public {
        vm.prank(attacker);
        vm.expectRevert(TollgateGuard.OnlyOwner.selector);
        guard.setPaused(true);
    }

    function test_admin_supportsIGuardInterface() public view {
        assertTrue(guard.supportsInterface(0xe6d7a83a));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // HELPER — builds ABI-encoded token data with TOKEN_PREFIX
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * @dev Builds the full data payload the Guard expects:
     *      [ TOKEN_PREFIX (4 bytes) ] [ abi.encode(token fields + signature) ]
     *
     *      Signs the correct EIP-712 digest using the provided private key.
     */
    function _buildTokenData(
        bytes32 tokenId,
        string  memory agentId,
        address dest,
        uint256 amountRaw,
        uint256 chainId,
        bytes32 nonce,
        uint256 expiresAt,
        bytes32 policyHash,
        uint256 signerKey
    ) internal view returns (bytes memory) {

        // Build domain separator matching what the Guard computed in constructor.
        bytes32 domainSep = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes("Tollgate")),
            keccak256(bytes("1")),
            block.chainid,            // must match Guard's chain
            address(guard)            // verifyingContract = Guard address
        ));

        // Build struct hash.
        bytes32 structHash = keccak256(abi.encode(
            APPROVAL_TOKEN_TYPEHASH,
            tokenId,
            keccak256(bytes(agentId)),
            dest,
            amountRaw,
            chainId,
            nonce,
            expiresAt,
            policyHash
        ));

        // Build EIP-712 digest.
        bytes32 digest = keccak256(abi.encodePacked(
            bytes2(0x1901),
            domainSep,
            structHash
        ));

        // Sign with Foundry cheatcode.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);

        // Pack signature as 65 bytes: r + s + v (matching go-ethereum format).
        bytes memory sig = abi.encodePacked(r, s, v);

        // ABI-encode the full token payload.
        bytes memory encoded = abi.encode(
            tokenId,
            agentId,
            dest,
            amountRaw,
            chainId,
            nonce,
            expiresAt,
            policyHash,
            sig
        );

        // Prepend the 4-byte TOKEN_PREFIX.
        return abi.encodePacked(bytes4(0x544F4C47), encoded);
    }
}
