/**
 * @file encoder.ts
 * injectTollgateToken — encodes an ApprovalToken into Safe transaction data.
 *
 * Output structure (concatenated, hex, no spaces):
 *   [ original calldata ] + [ 544F4C47 ] + [ ABI-encoded ApprovalTokenData ]
 *
 * The Phase 2 Guard reads this by:
 *   1. Scanning data backwards for the 0x544F4C47 prefix
 *   2. Slicing everything after it
 *   3. abi.decode(slice, ApprovalTokenData)
 *   4. Verifying the EIP-712 signature against notaryAddress
 */

import { encodeAbiParameters } from 'viem';
import { ApprovalToken, APPROVAL_TOKEN_ABI, TOLLGATE_PREFIX } from './types.js';

// ── CONVERSION HELPERS ────────────────────────────────────────────────────────

/**
 * Converts a UUID string to a bytes32 hex value.
 * Strips hyphens, converts to hex, pads to 64 hex chars (32 bytes).
 *
 * e.g. "123e4567-e89b-12d3-a456-426614174000"
 *   → "0x123e4567e89b12d3a456426614174000000000000000000000000000000000000"
 */
export function uuidToBytes32(uuid: string): `0x${string}` {
  const hex = uuid.replace(/-/g, '').padEnd(64, '0').slice(0, 64);
  return `0x${hex}`;
}

/**
 * Converts a string to bytes32 by UTF-8 encoding then zero-padding.
 * Truncates to 32 bytes if longer.
 *
 * Used for the nonce field which is a string in the token but bytes32 on-chain.
 */
export function stringToBytes32(str: string): `0x${string}` {
  const hex = Buffer.from(str, 'utf8').toString('hex');
  const padded = hex.padEnd(64, '0').slice(0, 64);
  return `0x${padded}`;
}

/**
 * Strips the 0x prefix from a hex string.
 * Returns the input unchanged if no prefix present.
 */
function strip0x(hex: string): string {
  return hex.startsWith('0x') || hex.startsWith('0X')
    ? hex.slice(2)
    : hex;
}

// ── MAIN ENCODER ─────────────────────────────────────────────────────────────

/**
 * Encodes an ApprovalToken into the Safe transaction data field.
 *
 * The Guard contract (TollgateGuard.sol) reads the token by scanning
 * the data field for the 4-byte TOLLGATE_PREFIX (0x544F4C47), then
 * ABI-decoding everything that follows it as ApprovalTokenData.
 *
 * Field order in encodeAbiParameters MUST match the Solidity struct:
 *   struct ApprovalTokenData {
 *     bytes32 tokenId;
 *     string  agentId;
 *     address destination;
 *     uint256 amountRaw;
 *     uint256 chainId;
 *     bytes32 nonce;
 *     uint256 expiresAt;
 *     bytes32 policyHash;
 *     bytes   signature;
 *   }
 *
 * @param originalData  Original transaction calldata. Pass '0x' if none.
 * @param token         ApprovalToken returned by the Phase 1 Notary.
 * @returns             Modified data field ready for Safe.execTransaction().
 */
export function injectTollgateToken(
  originalData: `0x${string}`,
  token: ApprovalToken,
): `0x${string}` {
  // Convert token_id UUID → bytes32
  const tokenIdBytes32 = uuidToBytes32(token.token_id);

  // Convert nonce string → bytes32
  const nonceBytes32 = stringToBytes32(token.nonce);

  // Convert expires_at ISO string → Unix timestamp as bigint
  const expiresAtUnix = BigInt(
    Math.floor(new Date(token.expires_at).getTime() / 1000),
  );

  // ABI-encode the struct using viem.
  // CRITICAL: tuple array format required for struct encoding in viem.
  const encoded = encodeAbiParameters(
    // ABI definition — field types in Solidity struct order
    APPROVAL_TOKEN_ABI as Parameters<typeof encodeAbiParameters>[0],
    // Values — must match the ABI order exactly
    [
      tokenIdBytes32                          as `0x${string}`, // bytes32
      token.agent_id,                                           // string
      token.destination as `0x${string}`,                      // address
      BigInt(token.amount_raw),                                 // uint256
      BigInt(token.chain_id),                                   // uint256
      nonceBytes32                            as `0x${string}`, // bytes32
      expiresAtUnix,                                            // uint256
      token.policy_hash as `0x${string}`,                      // bytes32
      token.signature   as `0x${string}`,                      // bytes
    ] as Parameters<typeof encodeAbiParameters<typeof APPROVAL_TOKEN_ABI>>[1],
  );

  // Concatenate: original(no 0x) + PREFIX(no 0x) + encoded(no 0x)
  const original = strip0x(originalData);
  const enc      = strip0x(encoded);

  return `0x${original}${TOLLGATE_PREFIX}${enc}`;
}

// ── INSPECTION HELPERS ────────────────────────────────────────────────────────

/**
 * Returns true if the data field already contains a Tollgate token.
 * Used in tests and for defensive checks before re-injecting.
 */
export function hasTollgateToken(data: `0x${string}`): boolean {
  return strip0x(data)
    .toLowerCase()
    .includes(TOLLGATE_PREFIX.toLowerCase());
}

/**
 * Returns the byte offset of the Tollgate prefix in data, or -1 if not found.
 * Useful for debugging encoding issues.
 */
export function findTollgatePrefixOffset(data: `0x${string}`): number {
  const hex = strip0x(data).toLowerCase();
  const prefix = TOLLGATE_PREFIX.toLowerCase();
  const byteIndex = hex.indexOf(prefix);
  return byteIndex === -1 ? -1 : byteIndex / 2; // convert nibble index to byte index
}