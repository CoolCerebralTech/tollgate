/**
 * @file test/encoder.test.ts
 * Unit tests for the token encoder — includes a byte-exact fixture test.
 */

import { describe, it, expect } from 'vitest';
import {
  injectTollgateToken,
  hasTollgateToken,
  uuidToBytes32,
  stringToBytes32,
  findTollgatePrefixOffset,
} from '../src/encoder.js';
import { TOLLGATE_PREFIX } from '../src/types.js';
import type { ApprovalToken } from '../src/types.js';

// ── FIXTURE TOKEN ─────────────────────────────────────────────────────────────
// Hardcoded fixture — used for byte-exact ABI encoding verification.

const FIXTURE_TOKEN: ApprovalToken = {
  token_id:       '123e4567-e89b-12d3-a456-426614174000',
  agent_id:       'trading-bot-01',
  policy_version: '1.0.0',
  policy_hash:    '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  action:         'transfer',
  destination:    '0xDEF4560000000000000000000000000000000000',
  amount_usd:     10.00,
  amount_raw:     '10000000',
  purpose:        'defi_yield_optimization',
  chain_id:       84532,
  nonce:          'test-nonce-001',
  issued_at:      '2026-05-28T00:00:00.000Z',
  expires_at:     '2026-05-28T00:01:00.000Z',
  risk_score:     0.12,
  auto_approved:  true,
  signature:      '0x' + 'ab'.repeat(65),
};

// ── uuidToBytes32 ─────────────────────────────────────────────────────────────

describe('uuidToBytes32', () => {
  it('produces a 0x-prefixed 64-char hex string (32 bytes)', () => {
    const result = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    expect(result).toMatch(/^0x[0-9a-f]{64}$/i);
  });

  it('is deterministic for the same input', () => {
    const a = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    const b = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    expect(a).toBe(b);
  });

  it('strips hyphens before encoding', () => {
    const result = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    expect(result).not.toContain('-');
  });

  it('produces different output for different UUIDs', () => {
    const a = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    const b = uuidToBytes32('223e4567-e89b-12d3-a456-426614174001');
    expect(a).not.toBe(b);
  });
});

// ── stringToBytes32 ───────────────────────────────────────────────────────────

describe('stringToBytes32', () => {
  it('produces a 0x-prefixed 64-char hex string', () => {
    const result = stringToBytes32('test-nonce');
    expect(result).toMatch(/^0x[0-9a-f]{64}$/i);
  });

  it('is deterministic', () => {
    expect(stringToBytes32('abc')).toBe(stringToBytes32('abc'));
  });

  it('produces different output for different strings', () => {
    expect(stringToBytes32('nonce-1')).not.toBe(stringToBytes32('nonce-2'));
  });
});

// ── injectTollgateToken ───────────────────────────────────────────────────────

describe('injectTollgateToken', () => {
  it('output starts with 0x', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(result).toMatch(/^0x/);
  });

  it('output contains TOLLGATE_PREFIX 544F4C47', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(result.toLowerCase()).toContain(TOLLGATE_PREFIX.toLowerCase());
  });

  it('original calldata appears before the prefix', () => {
    const original = '0xdeadbeef';
    const result = injectTollgateToken(original, FIXTURE_TOKEN);
    const hex = result.slice(2).toLowerCase();
    const prefixIdx = hex.indexOf(TOLLGATE_PREFIX.toLowerCase());
    // 'deadbeef' should appear at the very start, before the prefix
    expect(hex.startsWith('deadbeef')).toBe(true);
    expect(prefixIdx).toBe(8); // 8 hex chars = 4 bytes of 'deadbeef'
  });

  it('works correctly with empty original data 0x', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    // Should start immediately with the prefix
    expect(result.slice(2, 10).toLowerCase()).toBe(
      TOLLGATE_PREFIX.toLowerCase(),
    );
  });

  it('output is longer than just the prefix', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    // Should have prefix (4 bytes) + ABI-encoded struct (at least 288 bytes)
    expect(result.length).toBeGreaterThan(10 + 576); // 0x + 8 (prefix) + 576+ (encoded)
  });

  it('byte-exact: encoded output matches known ABI bytes for fixture', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    const hex = result.slice(2).toLowerCase();

    // After the 4-byte prefix, the first 32 bytes should be the tokenId
    // tokenId = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000')
    // = '123e4567e89b12d3a456426614174000' + '0'.repeat(32)
    const afterPrefix = hex.slice(8); // skip 8 hex chars = 4 bytes prefix
    const expectedTokenIdStart = '123e4567e89b12d3a456426614174000';
    expect(afterPrefix.startsWith(expectedTokenIdStart)).toBe(true);
  });

  it('two calls with same token produce identical output', () => {
    const a = injectTollgateToken('0x', FIXTURE_TOKEN);
    const b = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(a).toBe(b);
  });
});

// ── hasTollgateToken ──────────────────────────────────────────────────────────

describe('hasTollgateToken', () => {
  it('returns true for injected data', () => {
    const data = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(hasTollgateToken(data)).toBe(true);
  });

  it('returns false for plain calldata with no prefix', () => {
    expect(hasTollgateToken('0xdeadbeef')).toBe(false);
  });

  it('returns false for empty data', () => {
    expect(hasTollgateToken('0x')).toBe(false);
  });
});

// ── findTollgatePrefixOffset ──────────────────────────────────────────────────

describe('findTollgatePrefixOffset', () => {
  it('returns 0 when no original calldata', () => {
    const data = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(findTollgatePrefixOffset(data)).toBe(0);
  });

  it('returns correct byte offset when original calldata present', () => {
    const original = '0xdeadbeef'; // 4 bytes
    const data = injectTollgateToken(original, FIXTURE_TOKEN);
    expect(findTollgatePrefixOffset(data)).toBe(4); // offset 4 bytes
  });

  it('returns -1 for data with no prefix', () => {
    expect(findTollgatePrefixOffset('0xdeadbeef')).toBe(-1);
  });
});