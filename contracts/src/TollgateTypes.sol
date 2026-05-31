// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title TollgateTypes
 * @notice EIP-712 type definitions and cryptographic primitives for Tollgate
 *         Approval Token verification.
 *
 * @dev CRITICAL CORRECTNESS REQUIREMENT:
 *      Every hash produced by this contract must be IDENTICAL to the hash
 *      produced by the Phase 1 Go Notary (internal/signing/approval.go).
 *      A single byte difference makes every signature verification fail.
 *
 *      Three things that must match the Go code exactly:
 *      1. The type string (field names, types, ORDER) — copied verbatim
 *      2. The domain separator fields (name, version, chainId, verifyingContract)
 *      3. The ABI encoding order of each field in _hashApprovalToken()
 *
 *      V normalization: Go's crypto.Sign() returns V as 0 or 1.
 *      Solidity's ecrecover expects V as 27 or 28.
 *      The _recoverSigner() function handles this — do not remove that line.
 */
abstract contract TollgateTypes {

    // ── APPROVAL TOKEN TYPE HASH ───────────────────────────────────────────
    //
    // keccak256 of the EIP-712 type string.
    // This string is LOCKED. Changing a single character changes the typeHash
    // and breaks compatibility with every existing Phase 1 Notary deployment.
    //
    // Field order here must be IDENTICAL to the Go struct definition in
    // internal/signing/approval.go — ApprovalToken type definition.
    bytes32 internal constant APPROVAL_TOKEN_TYPEHASH = keccak256(
        "ApprovalToken(bytes32 tokenId,string agentId,address destination,uint256 amountRaw,uint256 chainId,bytes32 nonce,uint256 expiresAt,bytes32 policyHash)"
    );

    // ── EIP-712 DOMAIN TYPE HASH ───────────────────────────────────────────
    //
    // Standard EIP-712 domain separator type string — never changes.
    bytes32 internal constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    // ── DOMAIN SEPARATOR ──────────────────────────────────────────────────
    //
    // Computed once in the inheriting contract's constructor via
    // _buildDomainSeparator() and stored here.
    // Binds all signatures to:
    //   - This specific application ("Tollgate")
    //   - This specific chain (block.chainid)
    //   - This specific contract (address(this))
    // A signature valid on Base Sepolia cannot be replayed on Base Mainnet.
    bytes32 internal _domainSeparator;

    // ── DOMAIN SEPARATOR BUILDER ──────────────────────────────────────────
    //
    // Call this in the constructor of the inheriting contract.
    // Uses address(this) — must be called after deployment, not at compile time.
    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes("Tollgate")),   // name  — must match Go: "Tollgate"
            keccak256(bytes("1")),           // version — must match Go: "1"
            block.chainid,                   // chainId — set at runtime
            address(this)                    // verifyingContract — the Guard address
        ));
    }

    // ── STRUCT HASH ───────────────────────────────────────────────────────
    //
    // Encodes one ApprovalToken's fields into a 32-byte hash per EIP-712.
    //
    // ENCODING RULES (EIP-712 Section 5.1):
    //   - Static types (bytes32, address, uint256): encoded directly via abi.encode
    //   - Dynamic types (string): keccak256'd before encoding
    //
    // Field order MUST match the type string and the Go code. Do not reorder.
    function _hashApprovalToken(
        bytes32 tokenId,
        string  memory agentId,
        address destination,
        uint256 amountRaw,
        uint256 chainId,
        bytes32 nonce,
        uint256 expiresAt,
        bytes32 policyHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            APPROVAL_TOKEN_TYPEHASH,
            tokenId,                        // bytes32 — encoded directly
            keccak256(bytes(agentId)),      // string  — keccak256 before encoding
            destination,                    // address — encoded directly
            amountRaw,                      // uint256 — encoded directly
            chainId,                        // uint256 — encoded directly
            nonce,                          // bytes32 — encoded directly
            expiresAt,                      // uint256 — encoded directly
            policyHash                      // bytes32 — encoded directly
        ));
    }

    // ── DIGEST ────────────────────────────────────────────────────────────
    //
    // Produces the final EIP-712 digest that gets signed and verified.
    //
    // Formula: keccak256("\x19\x01" || domainSeparator || structHash)
    // The 0x1901 prefix is mandated by EIP-712 — it prevents collision with
    // EIP-191 personal_sign messages.
    //
    // This digest is what Phase 1's crypto.Sign() signed.
    // This digest is what ecrecover must verify against.
    function _getDigest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(
            bytes2(0x1901),      // EIP-712 magic prefix — required
            _domainSeparator,    // domain separator — chain + contract bound
            structHash           // struct hash — content bound
        ));
    }

    // ── SIGNATURE RECOVERY ────────────────────────────────────────────────
    //
    // Recovers the signer address from a digest and a 65-byte ECDSA signature.
    // Returns address(0) if the signature is malformed — caller must check.
    //
    // SECURITY: Returns address(0) on any malformed input rather than
    // reverting. The caller (TollgateGuard.checkTransaction) checks the
    // recovered address and reverts with SignatureInvalid() if it is wrong.
    // This prevents a malformed signature from causing an unexpected revert
    // that could be exploited to bypass the guard via a try/catch pattern.
    //
    // V NORMALIZATION — DO NOT REMOVE:
    // Go's go-ethereum crypto.Sign() returns V as 0 or 1 (recovery ID).
    // Solidity's ecrecover expects V as 27 or 28 (Ethereum standard).
    // Phase 1 signer.go adjusts V before returning: sig[64] += 27
    // This line is a second safety net for any edge cases.
    function _recoverSigner(
        bytes32 digest,
        bytes memory sig
    ) internal pure returns (address) {
        // Malformed signature — not 65 bytes (r=32, s=32, v=1)
        if (sig.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8   v;

        // Extract r, s, v from the packed signature bytes using assembly.
        // This is the standard pattern — cheaper than abi.decode for fixed layout.
        assembly {
            r := mload(add(sig, 0x20))   // bytes 1-32
            s := mload(add(sig, 0x40))   // bytes 33-64
            v := byte(0, mload(add(sig, 0x60))) // byte 65
        }

        // V normalization: Go returns 0/1, ecrecover needs 27/28.
        // Phase 1 already adjusts this in signer.go (sig[64] += 27),
        // but we normalize here as a safety net.
        if (v < 27) v += 27;

        // Reject invalid V values — only 27 and 28 are valid.
        if (v != 27 && v != 28) return address(0);

        // Reject malleable signatures (s in upper half of curve order).
        // EIP-2 mandates s <= secp256k1n/2 for canonical signatures.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }

        return ecrecover(digest, v, r, s);
    }

    // ── VIEW HELPERS ──────────────────────────────────────────────────────

    /// @notice Returns the domain separator for external verification.
    /// Used by the SDK and integration tests to confirm the Guard is
    /// using the correct domain before submitting transactions.
    function getDomainSeparator() external view returns (bytes32) {
        return _domainSeparator;
    }

    /// @notice Returns the ApprovalToken type hash for external verification.
    /// Auditors and integrators can confirm this matches the Phase 1 Notary.
    function getApprovalTokenTypeHash() external pure returns (bytes32) {
        return APPROVAL_TOKEN_TYPEHASH;
    }
}
