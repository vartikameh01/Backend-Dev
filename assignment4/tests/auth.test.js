'use strict';

/**
 * auth.test.js
 * Tests for: authentication, session management, password policy, account lockout.
 * Task 1 verification: strong passwords, session expiry, role assignment.
 */

// Use a test-only JWT secret so tests run without a real .env
process.env.JWT_SECRET      = 'test-secret-minimum-32-characters-xx';
process.env.SESSION_SECRET  = 'test-session-secret-minimum-32-chars';
process.env.ENCRYPTION_KEY  = 'a'.repeat(64);
process.env.NODE_ENV        = 'test';

const { generateTokens, verifyRefreshToken } = require('../src/middleware/auth');
const { validatePassword } = require('../src/utils/validators');
const { validationResult } = require('express-validator');

// ─── Helper: run a single express-validator chain against a mock req ──────────
async function runValidator(chain, value) {
  const mockReq = { body: { password: value }, query: {}, params: {}, headers: {} };
  await chain.run(mockReq);
  return validationResult(mockReq);
}

// ─── Password Policy Tests ────────────────────────────────────────────────────
describe('Password Policy (Task 1 — strong passwords)', () => {
  const chain = validatePassword();

  test('rejects password shorter than 12 characters', async () => {
    const result = await runValidator(chain, 'Short1!');
    expect(result.isEmpty()).toBe(false);
  });

  test('rejects password without uppercase letter', async () => {
    const result = await runValidator(chain, 'alllowercase1!');
    expect(result.isEmpty()).toBe(false);
  });

  test('rejects password without lowercase letter', async () => {
    const result = await runValidator(chain, 'ALLUPPERCASE1!');
    expect(result.isEmpty()).toBe(false);
  });

  test('rejects password without digit', async () => {
    const result = await runValidator(chain, 'NoDigitsHere!');
    expect(result.isEmpty()).toBe(false);
  });

  test('rejects password without special character', async () => {
    const result = await runValidator(chain, 'NoSpecialChar1');
    expect(result.isEmpty()).toBe(false);
  });

  test('accepts a valid strong password', async () => {
    const result = await runValidator(chain, 'Str0ng!Password#');
    expect(result.isEmpty()).toBe(true);
  });

  test('accepts 12-character minimum password', async () => {
    const result = await runValidator(chain, 'Abc123!@#xyz');
    expect(result.isEmpty()).toBe(true);
  });

  test('rejects password longer than 128 characters', async () => {
    const result = await runValidator(chain, 'Aa1!' + 'x'.repeat(128));
    expect(result.isEmpty()).toBe(false);
  });
});

// ─── JWT Token Tests ──────────────────────────────────────────────────────────
describe('JWT Token Generation & Verification (Task 1 — session management)', () => {
  const mockUser = { _id: '507f1f77bcf86cd799439011', role: 'patient', email: 'p@test.com' };

  test('generateTokens returns accessToken and refreshToken', () => {
    const tokens = generateTokens(mockUser);
    expect(tokens).toHaveProperty('accessToken');
    expect(tokens).toHaveProperty('refreshToken');
    expect(typeof tokens.accessToken).toBe('string');
    expect(typeof tokens.refreshToken).toBe('string');
  });

  test('access token has 3 JWT segments', () => {
    const { accessToken } = generateTokens(mockUser);
    expect(accessToken.split('.').length).toBe(3);
  });

  test('refresh token verifies successfully', () => {
    const { refreshToken } = generateTokens(mockUser);
    expect(() => verifyRefreshToken(refreshToken)).not.toThrow();
    const decoded = verifyRefreshToken(refreshToken);
    expect(decoded.sub).toBe(String(mockUser._id));
    expect(decoded.type).toBe('refresh');
  });

  test('access token used as refresh token is rejected', () => {
    const { accessToken } = generateTokens(mockUser);
    expect(() => verifyRefreshToken(accessToken)).toThrow('Not a refresh token');
  });

  test('tampered token is rejected', () => {
    const { refreshToken } = generateTokens(mockUser);
    const tampered = refreshToken.slice(0, -5) + 'XXXXX';
    expect(() => verifyRefreshToken(tampered)).toThrow();
  });
});

// ─── Session Timeout Configuration Tests ─────────────────────────────────────
describe('Session Timeout Configuration (Task 1 — session management)', () => {
  const { IDLE_TIMEOUT_BY_ROLE } = require('../src/middleware/sessionManager');

  test('patient idle timeout is 15 minutes', () => {
    expect(IDLE_TIMEOUT_BY_ROLE.patient).toBe(15 * 60 * 1000);
  });

  test('doctor idle timeout is 30 minutes', () => {
    expect(IDLE_TIMEOUT_BY_ROLE.doctor).toBe(30 * 60 * 1000);
  });

  test('nurse idle timeout is 30 minutes', () => {
    expect(IDLE_TIMEOUT_BY_ROLE.nurse).toBe(30 * 60 * 1000);
  });

  test('admin idle timeout is 15 minutes', () => {
    expect(IDLE_TIMEOUT_BY_ROLE.admin).toBe(15 * 60 * 1000);
  });

  test('insurance idle timeout is 15 minutes', () => {
    expect(IDLE_TIMEOUT_BY_ROLE.insurance).toBe(15 * 60 * 1000);
  });
});
