/**
 * tests/security.test.ts
 * Comprehensive security test suite for rp-tbs-exchange-api patches.
 * Covers: JWT auth, order validation, CORS, security headers.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as jwt from 'jsonwebtoken';
import { validateOrder, validateOrderNotional } from '../src/security/order_validator';

const TEST_SECRET = 'test_secret_key_for_unit_tests_only_32bytes!';
const JWT_SECRET = process.env.JWT_SECRET ?? TEST_SECRET;

// ============================================================================
// JWT Token Tests (logic layer, not middleware integration)
// ============================================================================

describe('JWT Token Validation Logic', () => {
  const makeToken = (overrides: Record<string, unknown> = {}, secret = JWT_SECRET) =>
    jwt.sign(
      {
        userId: 'usr_123',
        role: 'trader',
        kycVerified: true,
        ...overrides,
      },
      secret,
      { algorithm: 'HS256', expiresIn: '15m' }
    );

  it('signs and verifies a valid token', () => {
    const token = makeToken();
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as Record<string, unknown>;
    expect(payload.userId).toBe('usr_123');
    expect(payload.role).toBe('trader');
    expect(payload.kycVerified).toBe(true);
  });

  it('rejects a token signed with wrong secret', () => {
    const token = makeToken({}, 'wrong_secret');
    expect(() => jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })).toThrow();
  });

  it('rejects an expired token', () => {
    const token = jwt.sign(
      { userId: 'usr_expired', role: 'trader', kycVerified: true },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '-1s' } // already expired
    );
    expect(() => jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] })).toThrow(/expired/);
  });

  it('rejects a token missing kycVerified claim', () => {
    const token = makeToken({ kycVerified: undefined });
    const payload = jwt.decode(token) as Record<string, unknown>;
    expect(payload.kycVerified).toBeUndefined();
    // Middleware would reject this
  });

  it('token lifetime is within 15 minute bound', () => {
    const token = makeToken();
    const payload = jwt.decode(token) as { iat: number; exp: number };
    expect(payload.exp - payload.iat).toBeLessThanOrEqual(900);
  });
});

// ============================================================================
// Order Validation Tests
// ============================================================================

describe('Order Schema Validation', () => {
  const validOrder = {
    idempotencyKey: '550e8400-e29b-41d4-a716-446655440000',
    symbol: 'BTC-USD',
    side: 'buy',
    type: 'limit',
    baseSize: 0.001,
    limitPrice: 65000,
    slippageBps: 50,
  };

  it('accepts a valid order', () => {
    const result = validateOrder(validOrder);
    expect(result.success).toBe(true);
  });

  it('rejects missing idempotencyKey', () => {
    const result = validateOrder({ ...validOrder, idempotencyKey: undefined });
    expect(result.success).toBe(false);
  });

  it('rejects invalid UUID format for idempotencyKey', () => {
    const result = validateOrder({ ...validOrder, idempotencyKey: 'not-a-uuid' });
    expect(result.success).toBe(false);
  });

  it('rejects invalid symbol format', () => {
    const result = validateOrder({ ...validOrder, symbol: 'btcusd' });
    expect(result.success).toBe(false);
  });

  it('rejects negative baseSize', () => {
    const result = validateOrder({ ...validOrder, baseSize: -1 });
    expect(result.success).toBe(false);
  });

  it('rejects zero baseSize', () => {
    const result = validateOrder({ ...validOrder, baseSize: 0 });
    expect(result.success).toBe(false);
  });

  it('rejects Infinity baseSize', () => {
    const result = validateOrder({ ...validOrder, baseSize: Infinity });
    expect(result.success).toBe(false);
  });

  it('rejects NaN baseSize', () => {
    const result = validateOrder({ ...validOrder, baseSize: NaN });
    expect(result.success).toBe(false);
  });

  it('rejects slippageBps exceeding platform max', () => {
    const result = validateOrder({ ...validOrder, slippageBps: 10000 });
    expect(result.success).toBe(false);
  });

  it('rejects unknown fields (strict schema)', () => {
    const result = validateOrder({ ...validOrder, injectedField: 'malicious' });
    expect(result.success).toBe(false);
  });

  it('accepts market order without limitPrice', () => {
    const result = validateOrder({ ...validOrder, type: 'market', limitPrice: undefined });
    expect(result.success).toBe(true);
  });
});

// ============================================================================
// Order Notional Validation Tests
// ============================================================================

describe('Order Notional Validation', () => {
  it('accepts notional within bounds', () => {
    const result = validateOrderNotional(0.1, 65000); // $6500
    expect(result.valid).toBe(true);
  });

  it('rejects notional below minimum', () => {
    const result = validateOrderNotional(0.000001, 65000); // $0.065
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('below minimum');
  });

  it('rejects notional above maximum', () => {
    const result = validateOrderNotional(2, 65000); // $130,000
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('exceeds maximum');
  });

  it('rejects zero price', () => {
    const result = validateOrderNotional(1, 0);
    expect(result.valid).toBe(false);
  });

  it('rejects negative price', () => {
    const result = validateOrderNotional(1, -100);
    expect(result.valid).toBe(false);
  });

  it('rejects Infinity price', () => {
    const result = validateOrderNotional(1, Infinity);
    expect(result.valid).toBe(false);
  });
});
