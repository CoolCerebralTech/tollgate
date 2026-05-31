// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGuard} from "./interfaces/IGuard.sol";
import {TollgateTypes} from "./TollgateTypes.sol";

/**
 * @title  TollgateGuard
 * @notice Gnosis Safe Guard that enforces Tollgate policy approval on every
 *         outgoing transaction. Every transaction leaving the Safe must carry
 *         a valid EIP-712 Approval Token signed by the registered Tollgate
 *         Notary address. Without a valid token the transaction reverts before
 *         execution — the money never moves.
 *
 * @dev    Implements IGuard. Attach to a Gnosis Safe via Safe.setGuard(address).
 *
 *         Verification pipeline in checkTransaction (11 steps, in order):
 *           1.  Caller must be the Safe (OnlySafe)
 *           2.  Guard must not be paused (GuardIsPaused)
 *           3.  Extract ApprovalToken from transaction data (TokenMissing)
 *           4.  Token must not be expired (TokenExpired)
 *           5.  Token nonce must not be consumed (TokenNonceReplayed)
 *           6.  Token chainId must match block.chainid (ChainIdMismatch)
 *           7.  Token destination must match actual to (DestinationMismatch)
 *           8.  Token amountRaw must match actual value (AmountMismatch)
 *           9.  EIP-712 signature must recover to notaryAddress (SignatureInvalid)
 *           10. Store pending nonce for checkAfterExecution
 *           11. Emit TransactionApproved
 *
 *         checkAfterExecution marks the nonce as consumed — replay prevention.
 */
contract TollgateGuard is IGuard, TollgateTypes {

    // ── CONSTANTS ─────────────────────────────────────────────────────────────

    /// @dev 4-byte prefix marking where the Approval Token begins in tx data.
    ///      bytes4(keccak256("tollgate.approval.v1")) — agreed with Phase 3 SDK.
    bytes4 internal constant TOKEN_PREFIX = 0x544F4C47;

    // ── IMMUTABLE STATE ───────────────────────────────────────────────────────

    /// @notice The Tollgate Notary address — only signatures from this address
    ///         are accepted. Derived from Phase 1 ECDSA signing key.
    ///         Phase 1 public address: 0x174394D59b5700b48Bd48B5F06c7B96e8e43b6b5
    address public immutable notaryAddress;

    /// @notice The Gnosis Safe this Guard is attached to.
    ///         Only this address may call checkTransaction and checkAfterExecution.
    address public immutable safeAddress;

    // ── MUTABLE STATE ─────────────────────────────────────────────────────────

    /// @notice Consumed token nonces — prevents Approval Token replay.
    ///         Once a nonce is marked true it can never be cleared.
    mapping(bytes32 => bool) public consumedNonces;

    /// @notice Emergency pause — when true ALL transactions are blocked.
    ///         Set by owner (the Safe itself) via setPaused().
    bool public paused;

    /// @notice Owner of this Guard — the Safe itself.
    ///         Only the owner may call setPaused().
    address public owner;

    /// @notice Transient nonce passed from checkTransaction to checkAfterExecution.
    ///         Reset to bytes32(0) after each transaction cycle.
    bytes32 private _pendingNonce;

    // ── STRUCTS ───────────────────────────────────────────────────────────────

    /// @dev In-memory representation of the ABI-decoded Approval Token.
    struct ApprovalTokenData {
        bytes32 tokenId;
        string  agentId;
        address destination;
        uint256 amountRaw;
        uint256 chainId;
        bytes32 nonce;
        uint256 expiresAt;
        bytes32 policyHash;
        bytes   signature;
    }

    // ── EVENTS ────────────────────────────────────────────────────────────────

    /// @notice Emitted when a transaction is approved and allowed to execute.
    event TransactionApproved(
        bytes32 indexed tokenId,
        address indexed destination,
        uint256         amountRaw,
        string          agentId,
        bytes32         policyHash
    );

    /// @notice Emitted when the Guard pause state changes.
    event GuardPaused(bool isPaused);

    // ── CUSTOM ERRORS ─────────────────────────────────────────────────────────

    error TokenMissing();
    error TokenExpired();
    error TokenNonceReplayed();
    error SignatureInvalid();
    error DestinationMismatch();
    error AmountMismatch();
    error ChainIdMismatch();
    error GuardIsPaused();
    error OnlySafe();
    error OnlyOwner();
    error ZeroAddress();

    // ── CONSTRUCTOR ───────────────────────────────────────────────────────────

    /**
     * @param _notaryAddress Tollgate Notary public address (from Phase 1).
     * @param _safeAddress   The Gnosis Safe this Guard will protect.
     */
    constructor(address _notaryAddress, address _safeAddress) {
        if (_notaryAddress == address(0)) revert ZeroAddress();
        if (_safeAddress   == address(0)) revert ZeroAddress();

        notaryAddress    = _notaryAddress;
        safeAddress      = _safeAddress;
        owner            = _safeAddress;
        paused           = false;
        _domainSeparator = _buildDomainSeparator();
    }

    // ── IGUARD IMPLEMENTATION ─────────────────────────────────────────────────

    /**
     * @notice Called by the Gnosis Safe BEFORE every transaction executes.
     *         Reverts if the Approval Token is missing, invalid, or expired.
     */
    function checkTransaction(
        address          to,
        uint256          value,
        bytes   calldata data,
        uint8            operation,
        uint256          safeTxGas,
        uint256          baseGas,
        uint256          gasPrice,
        address          gasToken,
        address payable  refundReceiver,
        bytes   memory   signatures,
        address          msgSender
    ) external override {
        // Suppress unused variable warnings.
        operation; safeTxGas; baseGas; gasPrice;
        gasToken; refundReceiver; signatures; msgSender;

        // CHECK 1: Only the Safe may call this.
        if (msg.sender != safeAddress) revert OnlySafe();

        // CHECK 2: Guard must not be paused.
        if (paused) revert GuardIsPaused();

        // CHECK 3: Extract Approval Token from data field.
        ApprovalTokenData memory token = _extractToken(data);

        // CHECK 4: Token must not be expired.
        if (block.timestamp > token.expiresAt) revert TokenExpired();

        // CHECK 5: Nonce must not have been consumed.
        if (consumedNonces[token.nonce]) revert TokenNonceReplayed();

        // CHECK 6: Chain ID must match this chain.
        if (token.chainId != block.chainid) revert ChainIdMismatch();

        // CHECK 7: Destination must match actual transaction target.
        if (token.destination != to) revert DestinationMismatch();

        // CHECK 8: Amount must match actual transaction value.
        if (token.amountRaw != value) revert AmountMismatch();

        // CHECK 9: Verify EIP-712 signature recovers to notaryAddress.
        bytes32 structHash = _hashApprovalToken(
            token.tokenId,
            token.agentId,
            token.destination,
            token.amountRaw,
            token.chainId,
            token.nonce,
            token.expiresAt,
            token.policyHash
        );
        bytes32 digest    = _getDigest(structHash);
        address recovered = _recoverSigner(digest, token.signature);
        if (recovered != notaryAddress) revert SignatureInvalid();

        // CHECK 10: Store pending nonce for checkAfterExecution.
        _pendingNonce = token.nonce;

        // CHECK 11: Emit approval event.
        emit TransactionApproved(
            token.tokenId,
            to,
            value,
            token.agentId,
            token.policyHash
        );
    }

    /**
     * @notice Called by the Safe AFTER every transaction executes.
     *         Marks the Approval Token nonce as consumed — prevents replay.
     */
    function checkAfterExecution(bytes32 txHash, bool success) external override {
        txHash; success;
        if (msg.sender != safeAddress) revert OnlySafe();
        if (_pendingNonce != bytes32(0)) {
            consumedNonces[_pendingNonce] = true;
            _pendingNonce = bytes32(0);
        }
    }

    // ── ADMIN ─────────────────────────────────────────────────────────────────

    /// @notice Pause or unpause the Guard. Only the owner (Safe) may call this.
    function setPaused(bool _paused) external {
        if (msg.sender != owner) revert OnlyOwner();
        paused = _paused;
        emit GuardPaused(_paused);
    }

    /// @notice Check whether a nonce has been consumed.
    function isNonceConsumed(bytes32 nonce) external view returns (bool) {
        return consumedNonces[nonce];
    }

    /// @notice EIP-165 — required by Gnosis Safe to recognise this as a Guard.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0xe6d7a83a;
    }

    // ── INTERNAL: TOKEN EXTRACTION ────────────────────────────────────────────

    /**
     * @dev Searches data for TOKEN_PREFIX, slices everything after it,
     *      and ABI-decodes it into ApprovalTokenData.
     *      Reverts TokenMissing() if prefix not found or data is malformed.
     */
    function _extractToken(
        bytes calldata data
    ) internal pure returns (ApprovalTokenData memory token) {
        if (data.length < 5) revert TokenMissing();

        // Search backwards for TOKEN_PREFIX — SDK always appends it last.
        uint256 prefixPos = type(uint256).max;

        if (data.length >= 4) {
            for (uint256 i = data.length - 4; ; ) {
                if (bytes4(data[i:i + 4]) == TOKEN_PREFIX) {
                    prefixPos = i;
                    break;
                }
                if (i == 0) break;
                unchecked { --i; }
            }
        }

        if (prefixPos == type(uint256).max) revert TokenMissing();

        bytes calldata encoded = data[prefixPos + 4:];
        if (encoded.length == 0) revert TokenMissing();

        (
            token.tokenId,
            token.agentId,
            token.destination,
            token.amountRaw,
            token.chainId,
            token.nonce,
            token.expiresAt,
            token.policyHash,
            token.signature
        ) = abi.decode(
            encoded,
            (bytes32, string, address, uint256, uint256, bytes32, uint256, bytes32, bytes)
        );
    }
}
