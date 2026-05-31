/**
 * @file types.ts
 * All type definitions, Zod schemas, ABI constants, and network constants.
 * Everything else in the SDK imports from here.
 */

import { z } from 'zod';

// ── APPROVAL TOKEN ──────────────────────────────────────────────────────────
// Mirrors the Phase 1 Notary approval_token JSON response exactly.
// snake_case field names match the Go JSON serialization.

export const ApprovalTokenSchema = z.object({
  token_id:       z.string().uuid(),
  agent_id:       z.string().min(1),
  policy_version: z.string(),
  policy_hash:    z.string().startsWith('0x'),
  action:         z.string(),
  destination:    z.string().startsWith('0x'),
  amount_usd:     z.number().positive(),
  amount_raw:     z.string().min(1),       // bigint as string — no float precision loss
  purpose:        z.string(),
  chain_id:       z.number().int().positive(),
  nonce:          z.string().min(1),
  issued_at:      z.string().datetime(),
  expires_at:     z.string().datetime(),
  risk_score:     z.number().min(0).max(1),
  auto_approved:  z.boolean(),
  signature:      z.string().startsWith('0x'), // 65-byte ECDSA sig, hex-encoded
});

export type ApprovalToken = z.infer<typeof ApprovalTokenSchema>;

// ── NOTARY RESPONSE ─────────────────────────────────────────────────────────
// Discriminated union on the status field — matches Phase 1 response exactly.

export const NotaryResponseSchema = z.discriminatedUnion('status', [
  z.object({
    status:         z.literal('approved'),
    decision_id:    z.string().uuid(),
    approval_token: ApprovalTokenSchema,
  }),
  z.object({
    status:      z.literal('denied'),
    decision_id: z.string().uuid(),
    code:        z.string(),
    message:     z.string(),
  }),
  z.object({
    status:      z.literal('pending_human'),
    decision_id: z.string().uuid(),
    message:     z.string(),
  }),
]);

export type NotaryResponse = z.infer<typeof NotaryResponseSchema>;

// ── REQUEST TYPES ───────────────────────────────────────────────────────────

/** What the developer passes to sendTransaction(). */
export interface TxRequest {
  to:         `0x${string}`;
  value:      bigint;          // exact on-chain amount in wei
  data?:      `0x${string}`; // original calldata — undefined means no calldata
  purpose:    string;          // must match policy.yaml allowed_purposes exactly
  amountUsd:  number;          // USD equivalent — Notary uses this for spend limits
}

/** Internal — what the SDK sends to POST /v1/action-check. */
export interface ActionRequest {
  agent_id:    string;
  action:      string;
  destination: string;
  amount_usd:  number;
  amount_raw:  string;   // bigint as string
  purpose:     string;
  chain_id:    number;
  nonce:       string;   // UUID v4 — unique per request, fresh on every retry
  timestamp:   string;   // ISO 8601 UTC
}

// ── CONFIG ──────────────────────────────────────────────────────────────────

export interface TollgateConfig {
  /** Phase 1 Notary URL — no trailing slash. e.g. http://localhost:8080 */
  notaryUrl: string;

  /** Bearer token from Phase 1 Notary startup log.
   *  SECURITY: never log this value. */
  agentToken: string;

  /** Registered agent ID in policy.yaml. e.g. "trading-bot-01" */
  agentId: string;

  /** Gnosis Safe address on Base that has TollgateGuard attached. */
  safeAddress: `0x${string}`;

  /** Safe owner private key — used to sign Safe transactions.
   *  SECURITY: never log this value. */
  ownerPrivateKey: `0x${string}`;

  // ── Optional behaviour ─────────────────────────────────────────────────

  /** Set true to use Base mainnet (chainId 8453). Default: false (Base Sepolia 84532). */
  useMainnet?: boolean;

  /** Default purpose if not specified per-transaction. */
  defaultPurpose?: string;

  /** Seconds before expiry to reject a token as too-close. Default: 10. */
  tokenExpiryBufferSeconds?: number;

  /** Milliseconds to wait for human approval before timeout. Default: 300_000 (5 min). */
  humanApprovalTimeoutMs?: number;

  /** Milliseconds between human approval polls. Default: 3_000. */
  humanApprovalPollIntervalMs?: number;

  /** Milliseconds before aborting a Notary HTTP request. Default: 10_000. */
  notaryTimeoutMs?: number;

  /** Max retry attempts on network failure. Default: 3. */
  maxRetries?: number;

  // ── Lifecycle callbacks ────────────────────────────────────────────────

  /** Fired when a transaction is awaiting human approval.
   *  sendTransaction() is still running — it has not returned yet. */
  onPendingHumanApproval?: (decisionId: string) => void;

  /** Fired when a pending transaction is approved by a human. */
  onHumanApprovalReceived?: (decisionId: string) => void;
}

// ── APPROVAL TOKEN ABI ──────────────────────────────────────────────────────
// ABI definition for the ApprovalTokenData struct in TollgateGuard.sol.
// Field ORDER must match the Solidity struct exactly — used by viem's
// encodeAbiParameters in encoder.ts.

export const APPROVAL_TOKEN_ABI = [
  { name: 'tokenId',     type: 'bytes32' },
  { name: 'agentId',     type: 'string'  },
  { name: 'destination', type: 'address' },
  { name: 'amountRaw',   type: 'uint256' },
  { name: 'chainId',     type: 'uint256' },
  { name: 'nonce',       type: 'bytes32' },
  { name: 'expiresAt',   type: 'uint256' },
  { name: 'policyHash',  type: 'bytes32' },
  { name: 'signature',   type: 'bytes'   },
] as const;

// ── NETWORK CONSTANTS ───────────────────────────────────────────────────────

export const BASE_MAINNET_CHAIN_ID = 8453;
export const BASE_SEPOLIA_CHAIN_ID = 84532;

/**
 * 4-byte prefix that marks the start of the Tollgate token in tx data.
 * bytes4(keccak256("tollgate.approval.v1")) — agreed with Phase 2 Guard.
 * No 0x prefix — raw hex, concatenated directly.
 */
export const TOLLGATE_PREFIX = '544F4C47' as const;