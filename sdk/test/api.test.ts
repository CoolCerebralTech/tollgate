/**
 * @file test/api.test.ts
 * Unit tests for TollgateClient using msw to mock HTTP.
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { TollgateClient } from '../src/api.js';
import {
  TollgateTransactionDeniedError,
  TollgateValidationError,
  TollgateNetworkError,
  TollgateNotaryUnreachableError,
} from '../src/errors.js';
import type { ActionRequest } from '../src/types.js';

// ── FIXTURES ──────────────────────────────────────────────────────────────────

const NOTARY_URL  = 'http://localhost:8080';
const AGENT_TOKEN = 'test-token-never-logged';

const validToken = {
  token_id:       '123e4567-e89b-12d3-a456-426614174000',
  agent_id:       'trading-bot-01',
  policy_version: '1.0.0',
  policy_hash:    '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  action:         'transfer',
  destination:    '0xdef4560000000000000000000000000000000000',
  amount_usd:     10.00,
  amount_raw:     '10000000',
  purpose:        'defi_yield_optimization',
  chain_id:       84532,
  nonce:          'test-nonce-001',
  issued_at:      new Date().toISOString(),
  expires_at:     new Date(Date.now() + 60_000).toISOString(),
  risk_score:     0.12,
  auto_approved:  true,
  signature:      '0x' + 'ab'.repeat(65),
};

const approvedResponse = {
  status:         'approved',
  decision_id:    '223e4567-e89b-12d3-a456-426614174001',
  approval_token: validToken,
};

const deniedResponse = {
  status:      'denied',
  decision_id: '323e4567-e89b-12d3-a456-426614174002',
  code:        'PURPOSE_MISMATCH',
  message:     'Purpose buy_nfts is not in allowed_purposes',
};

const baseRequest: ActionRequest = {
  agent_id:    'trading-bot-01',
  action:      'transfer',
  destination: '0xdef4560000000000000000000000000000000000',
  amount_usd:  10.00,
  amount_raw:  '10000000',
  purpose:     'defi_yield_optimization',
  chain_id:    84532,
  nonce:       'test-nonce-001',
  timestamp:   new Date().toISOString(),
};

// ── MSW SERVER ────────────────────────────────────────────────────────────────

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// ── HELPERS ───────────────────────────────────────────────────────────────────

function makeClient(overrides?: Partial<{ timeoutMs: number; maxRetries: number }>) {
  return new TollgateClient(
    NOTARY_URL,
    AGENT_TOKEN,
    overrides?.timeoutMs  ?? 5_000,
    overrides?.maxRetries ?? 0, // no retries by default in unit tests
  );
}

// ── TESTS ─────────────────────────────────────────────────────────────────────

describe('TollgateClient.requestApproval', () => {

  it('returns ApprovalToken on approved response', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json(approvedResponse),
      ),
    );
    const client = makeClient();
    const result = await client.requestApproval(baseRequest);
    expect(result.status).toBe('approved');
    if (result.status === 'approved') {
      expect(result.approval_token.token_id).toBe(validToken.token_id);
      expect(result.approval_token.signature).toMatch(/^0x/);
    }
  });

  it('returns denied response on policy denial', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json(deniedResponse),
      ),
    );
    const client = makeClient();
    const result = await client.requestApproval(baseRequest);
    expect(result.status).toBe('denied');
    if (result.status === 'denied') {
      expect(result.code).toBe('PURPOSE_MISMATCH');
    }
  });

  it('throws TollgateValidationError on malformed response', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json({ broken: true, no_status: 'field' }),
      ),
    );
    const client = makeClient();
    await expect(client.requestApproval(baseRequest))
      .rejects.toBeInstanceOf(TollgateValidationError);
  });

  it('throws TollgateNetworkError on 401 and does NOT retry', async () => {
    let callCount = 0;
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () => {
        callCount++;
        return HttpResponse.json({ error: 'unauthorized' }, { status: 401 });
      }),
    );
    const client = makeClient({ maxRetries: 3 });
    await expect(client.requestApproval(baseRequest))
      .rejects.toBeInstanceOf(TollgateNetworkError);
    // Must not retry on 401.
    expect(callCount).toBe(1);
  });

  it('throws TollgateNetworkError on 429 rate limit', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json({ error: 'rate limited' }, { status: 429 }),
      ),
    );
    const client = makeClient();
    await expect(client.requestApproval(baseRequest))
      .rejects.toBeInstanceOf(TollgateNetworkError);
  });

  it('retries on network error and succeeds on 3rd attempt', async () => {
    let callCount = 0;
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () => {
        callCount++;
        if (callCount < 3) {
          return HttpResponse.error(); // network failure
        }
        return HttpResponse.json(approvedResponse);
      }),
    );
    const client = makeClient({ maxRetries: 3 });
    const result = await client.requestApproval(baseRequest);
    expect(result.status).toBe('approved');
    expect(callCount).toBe(3);
  });

  it('each retry generates a fresh nonce', async () => {
    const nonces: string[] = [];
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, async ({ request }) => {
        const body = await request.json() as ActionRequest;
        nonces.push(body.nonce);
        if (nonces.length < 3) return HttpResponse.error();
        return HttpResponse.json(approvedResponse);
      }),
    );
    const client = makeClient({ maxRetries: 3 });
    await client.requestApproval(baseRequest);
    // All nonces must be unique.
    const unique = new Set(nonces);
    expect(unique.size).toBe(nonces.length);
  });

  it('agentToken does not appear in any thrown error', async () => {
    server.use(
      http.post(`${NOTARY_URL}/v1/action-check`, () =>
        HttpResponse.json({ error: 'unauthorized' }, { status: 401 }),
      ),
    );
    const client = makeClient();
    try {
      await client.requestApproval(baseRequest);
      expect.fail('should have thrown');
    } catch (err) {
      const errStr = JSON.stringify(err) + String(err);
      expect(errStr).not.toContain(AGENT_TOKEN);
    }
  });
});

describe('TollgateClient.healthCheck', () => {

  it('returns true when Notary responds 200', async () => {
    server.use(
      http.get(`${NOTARY_URL}/v1/health`, () =>
        HttpResponse.json({ status: 'ok' }),
      ),
    );
    const client = makeClient();
    await expect(client.healthCheck()).resolves.toBe(true);
  });

  it('throws TollgateNotaryUnreachableError when Notary is down', async () => {
    server.use(
      http.get(`${NOTARY_URL}/v1/health`, () => HttpResponse.error()),
    );
    const client = makeClient();
    await expect(client.healthCheck())
      .rejects.toBeInstanceOf(TollgateNotaryUnreachableError);
  });
});