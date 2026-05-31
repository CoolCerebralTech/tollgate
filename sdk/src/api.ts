/**
 * @file api.ts
 * TollgateClient — all HTTP communication with the Phase 1 Notary.
 *
 * SECURITY CONTRACT:
 *   - agentToken is NEVER logged, never included in error messages,
 *     never thrown in any value. It lives only in the Authorization header.
 *   - Each retry generates a FRESH nonce via the nonceFactory parameter.
 *     Reusing a nonce on retry would cause NONCE_REPLAY denial.
 *   - 4xx responses are NEVER retried — a denial is a final answer.
 *   - Only network-level failures trigger retries (fetch throws, ECONNREFUSED).
 */

import { z } from 'zod';
import {
  NotaryResponseSchema,
  NotaryResponse,
  ActionRequest,
} from './types.js';
import {
  TollgateNetworkError,
  TollgateTimeoutError,
  TollgateNotaryUnreachableError,
  TollgateValidationError,
  TollgateHumanApprovalTimeoutError,
} from './errors.js';

// ── DECISION ENDPOINT SCHEMA ─────────────────────────────────────────────────
// GET /v1/decision/:id returns the same shape as /v1/action-check.
const DecisionResponseSchema = NotaryResponseSchema;

// ── EXPONENTIAL BACKOFF ───────────────────────────────────────────────────────
const RETRY_DELAYS_MS = [0, 1_000, 2_000, 4_000] as const;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── CLIENT ────────────────────────────────────────────────────────────────────

export class TollgateClient {
  constructor(
    private readonly baseUrl: string,
    private readonly agentToken: string,
    private readonly timeoutMs: number = 10_000,
    private readonly maxRetries: number = 3,
  ) {}

  // ── requestApproval ─────────────────────────────────────────────────────────

  /**
   * POST /v1/action-check
   *
   * Sends the ActionRequest to the Notary and returns a validated
   * NotaryResponse. On network failure: retries up to maxRetries times
   * with exponential backoff. Each retry gets a fresh nonce via nonceFactory.
   *
   * @param request       The action request to evaluate.
   * @param nonceFactory  Called before each attempt to get a fresh nonce.
   *                      Prevents NONCE_REPLAY on retry.
   */
  async requestApproval(
    request: ActionRequest,
    nonceFactory: () => string = () => crypto.randomUUID(),
  ): Promise<NotaryResponse> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      // Wait before retry (first attempt has 0 delay).
      const delay = RETRY_DELAYS_MS[attempt] ?? 4_000;
      if (attempt > 0) {
        await sleep(delay);
      }

      // Fresh nonce on every attempt — prevents NONCE_REPLAY.
      const requestWithFreshNonce: ActionRequest = {
        ...request,
        nonce:     nonceFactory(),
        timestamp: new Date().toISOString(),
      };

      try {
        const response = await this._post(
          '/v1/action-check',
          requestWithFreshNonce,
        );

        // 4xx = final answer — do NOT retry.
        if (response.status === 401 || response.status === 403) {
          throw new TollgateNetworkError(
            null,
            `Notary rejected agent token (HTTP ${response.status})`,
          );
        }
        if (response.status === 429) {
          throw new TollgateNetworkError(null, 'Rate limited by Notary');
        }
        if (response.status >= 400 && response.status < 500) {
          throw new TollgateNetworkError(
            null,
            `Notary returned HTTP ${response.status}`,
          );
        }

        const json: unknown = await response.json();
        return this._validate(json);
      } catch (err) {
        // Re-throw immediately for errors that must not be retried.
        if (err instanceof TollgateNetworkError) throw err;
        if (err instanceof TollgateValidationError) throw err;
        if (err instanceof TollgateTimeoutError) throw err;

        // Network-level failure — eligible for retry.
        lastError = err;
        if (attempt < this.maxRetries) {
          continue;
        }
      }
    }

    throw new TollgateNetworkError(
      lastError,
      `Notary unreachable after ${this.maxRetries + 1} attempts`,
    );
  }

  // ── pollDecision ─────────────────────────────────────────────────────────────

  /**
   * GET /v1/decision/:id
   *
   * Polls until the decision is no longer pending_human.
   * Used when sendTransaction receives a pending_human response.
   *
   * @param decisionId   The UUID from the pending response.
   * @param intervalMs   Poll interval in milliseconds.
   * @param timeoutMs    Max total wait time before throwing.
   * @param onPoll       Optional callback fired before each poll attempt.
   */
  async pollDecision(
    decisionId: string,
    intervalMs: number,
    timeoutMs: number,
    onPoll?: () => void,
  ): Promise<NotaryResponse> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      onPoll?.();

      try {
        const response = await this._get(`/v1/decision/${decisionId}`);
        if (response.ok) {
          const json: unknown = await response.json();
          const parsed = this._validate(json);
          if (parsed.status !== 'pending_human') {
            return parsed;
          }
        }
      } catch {
        // Poll failures are transient — keep trying until timeout.
      }

      await sleep(intervalMs);
    }

    throw new TollgateHumanApprovalTimeoutError(decisionId, timeoutMs);
  }

  // ── healthCheck ──────────────────────────────────────────────────────────────

  /**
   * GET /v1/health
   *
   * Verifies the Notary is reachable and reports status ok.
   * Called by TollgateSigner.create() before returning the instance.
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this._get('/v1/health');
      if (!response.ok) {
        throw new TollgateNotaryUnreachableError(this.baseUrl);
      }
      return true;
    } catch (err) {
      if (err instanceof TollgateNotaryUnreachableError) throw err;
      throw new TollgateNotaryUnreachableError(this.baseUrl);
    }
  }

  // ── PRIVATE HELPERS ──────────────────────────────────────────────────────────

  /**
   * POST with JSON body. AbortController enforces the timeout.
   * SECURITY: Authorization header carries the agentToken — it is never
   * logged, never included in error messages.
   */
  private async _post(path: string, body: unknown): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await fetch(`${this.baseUrl}${path}`, {
        method:  'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${this.agentToken}`,
        },
        body:   JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new TollgateTimeoutError(this.timeoutMs);
      }
      throw err; // Network error — will be caught by retry loop above.
    } finally {
      clearTimeout(timer);
    }
  }

  /** GET with auth header. No retry logic — caller handles polling. */
  private async _get(path: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await fetch(`${this.baseUrl}${path}`, {
        method:  'GET',
        headers: {
          'Authorization': `Bearer ${this.agentToken}`,
        },
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new TollgateTimeoutError(this.timeoutMs);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Validates the raw JSON response against NotaryResponseSchema. */
  private _validate(json: unknown): NotaryResponse {
    const result = NotaryResponseSchema.safeParse(json);
    if (!result.success) {
      throw new TollgateValidationError(result.error);
    }
    return result.data;
  }
}