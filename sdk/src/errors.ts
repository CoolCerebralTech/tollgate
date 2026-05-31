/**
 * @file errors.ts
 * All Tollgate SDK error classes.
 * Every error extends TollgateError so developers can catch the whole family
 * with a single `catch (e) { if (e instanceof TollgateError) ... }`.
 */

// ── BASE ERROR ──────────────────────────────────────────────────────────────

export class TollgateError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(`[Tollgate/${code}] ${message}`);
    this.name = 'TollgateError';
    // Fix instanceof checks in compiled/transpiled JS
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ── CONFIG ERRORS ───────────────────────────────────────────────────────────

/** Thrown when a required config field is missing or invalid. */
export class TollgateConfigError extends TollgateError {
  constructor(msg: string) {
    super('CONFIG', msg);
    this.name = 'TollgateConfigError';
  }
}

// ── NETWORK ERRORS ──────────────────────────────────────────────────────────

/** Thrown on fetch failure (ECONNREFUSED, DNS, etc.) after all retries. */
export class TollgateNetworkError extends TollgateError {
  constructor(
    public readonly cause: unknown,
    msg: string,
  ) {
    super('NETWORK', msg);
    this.name = 'TollgateNetworkError';
  }
}

/** Thrown when a Notary request exceeds the configured timeout. */
export class TollgateTimeoutError extends TollgateError {
  constructor(ms: number) {
    super('TIMEOUT', `Notary request timed out after ${ms}ms`);
    this.name = 'TollgateTimeoutError';
  }
}

/** Thrown by healthCheck() when the Notary is not reachable. */
export class TollgateNotaryUnreachableError extends TollgateError {
  constructor(url: string) {
    super('UNREACHABLE', `Notary not reachable at ${url}. Is it running?`);
    this.name = 'TollgateNotaryUnreachableError';
  }
}

// ── POLICY ERRORS ───────────────────────────────────────────────────────────

/**
 * Thrown when the Notary denies the transaction.
 * Contains the exact denial code and message from Phase 1 for debugging.
 *
 * SECURITY: denialCode and denialMessage come from the Notary — they
 * never contain the agent token or any secret values.
 */
export class TollgateTransactionDeniedError extends TollgateError {
  constructor(
    public readonly denialCode: string,
    public readonly denialMessage: string,
  ) {
    super('DENIED', `[${denialCode}] ${denialMessage}`);
    this.name = 'TollgateTransactionDeniedError';
  }
}

/** Thrown when a human approval times out waiting for a decision. */
export class TollgateHumanApprovalTimeoutError extends TollgateError {
  constructor(decisionId: string, ms: number) {
    super(
      'HUMAN_TIMEOUT',
      `Human approval timed out after ${ms}ms. Decision ID: ${decisionId}`,
    );
    this.name = 'TollgateHumanApprovalTimeoutError';
  }
}

/**
 * Thrown when the token expiry is too close to safely submit the transaction.
 * The SDK rejects it before hitting the chain to avoid a Guard revert.
 */
export class TollgateTokenExpiredError extends TollgateError {
  constructor(tokenId: string, expiresAt: string) {
    super(
      'TOKEN_EXPIRED',
      `Token ${tokenId} expires at ${expiresAt} — too close to expiry to submit safely`,
    );
    this.name = 'TollgateTokenExpiredError';
  }
}

// ── VALIDATION ERRORS ───────────────────────────────────────────────────────

/**
 * Thrown when the Notary returns a response that fails Zod schema validation.
 * Means the Notary API shape changed or the response was malformed.
 */
export class TollgateValidationError extends TollgateError {
  constructor(public readonly cause: unknown) {
    super('VALIDATION', 'Notary returned an unexpected response shape. Check Notary version.');
    this.name = 'TollgateValidationError';
  }
}

// ── ON-CHAIN ERRORS ─────────────────────────────────────────────────────────

/**
 * Thrown when the Safe transaction reverts on-chain.
 * This should not happen if the token is valid — it indicates a Guard
 * configuration mismatch or the token was already consumed.
 */
export class TollgateOnChainError extends TollgateError {
  constructor(
    public readonly txHash: `0x${string}`,
    public readonly guardError: string,
  ) {
    super('ONCHAIN', `Transaction reverted: ${guardError}. txHash: ${txHash}`);
    this.name = 'TollgateOnChainError';
  }
}