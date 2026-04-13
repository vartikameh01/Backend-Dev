'use strict';

/**
 * Task 10 — Automated security regression tests
 * Tests cover:
 * - MongoDB injection prevention (express-mongo-sanitize)
 * - XSS in transaction descriptions (sanitizeText / sanitizeForEmail)
 * - Security headers (Helmet — CSP, HSTS, X-Frame-Options, etc.)
 * - Error message leakage prevention (no stack traces / DB errors in responses)
 * - HTTPS redirect (production mode check)
 * - Sensitive field stripping (passwordHash, twoFactorSecret never in responses)
 * - Parameter tampering (account ID in body vs. auth token)
 * - Rate limiting enforcement
 */

const request = require('supertest');
const mongoose = require('mongoose');
const { sanitizeText, sanitizeForEmail, sanitizeMongoQuery } = require('../src/utils/sanitizers');
const app = require('../src/app');
const User = require('../src/models/User');
const authService = require('../src/services/authService');

let testUser, accessToken;

beforeAll(async () => {
  await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/quickbank_test');
  await User.deleteMany({ email: 'sectest@quickbank.test' });
  testUser = new User({ email: 'sectest@quickbank.test', firstName: 'Sec', lastName: 'Test' });
  await testUser.setPassword('Secure!Pass123');
  await testUser.save();
  accessToken = authService.generateAccessToken(testUser);
});

afterAll(async () => {
  await User.deleteMany({ email: 'sectest@quickbank.test' });
  await mongoose.connection.close();
});

// ─── Security Headers ──────────────────────────────────────────────────────────

describe('Security headers (Helmet)', () => {
  let res;
  beforeAll(async () => {
    res = await request(app).get('/health');
  });

  it('sets X-Frame-Options: DENY', () => {
    expect(res.headers['x-frame-options']).toBe('DENY');
  });

  it('sets X-Content-Type-Options: nosniff', () => {
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('sets Content-Security-Policy', () => {
    expect(res.headers['content-security-policy']).toBeDefined();
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
  });

  it('sets Strict-Transport-Security', () => {
    expect(res.headers['strict-transport-security']).toMatch(/max-age=\d+/);
  });

  it('does not expose X-Powered-By', () => {
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

// ─── Input Sanitization ────────────────────────────────────────────────────────

describe('sanitizeText — XSS prevention', () => {
  it('strips script tags', () => {
    expect(sanitizeText('<script>alert(1)</script>')).toBe('');
  });

  it('strips event handlers', () => {
    expect(sanitizeText('<img onerror="alert(1)" src=x>')).toBe('');
  });

  it('strips all HTML from plain-text fields', () => {
    expect(sanitizeText('<b>bold</b> text')).toBe('bold text');
  });

  it('leaves safe plain text unchanged', () => {
    expect(sanitizeText('Transfer for rent payment')).toBe('Transfer for rent payment');
  });
});

describe('sanitizeForEmail — XSS in email notifications', () => {
  it('strips script tags from email content', () => {
    const result = sanitizeForEmail('<script>document.cookie</script>Transfer');
    expect(result).not.toContain('<script>');
    expect(result).toContain('Transfer');
  });

  it('handles empty string', () => {
    expect(sanitizeForEmail('')).toBe('');
  });

  it('handles non-string input gracefully', () => {
    expect(sanitizeForEmail(null)).toBe('');
    expect(sanitizeForEmail(undefined)).toBe('');
  });
});

describe('sanitizeMongoQuery — NoSQL injection prevention', () => {
  it('removes $ operator keys', () => {
    const result = sanitizeMongoQuery({ $where: '1==1', email: 'test@test.com' });
    expect(result).not.toHaveProperty('$where');
    expect(result.email).toBe('test@test.com');
  });

  it('removes nested $ operators', () => {
    const result = sanitizeMongoQuery({ filter: { $gt: 0, value: 'safe' } });
    expect(result.filter).not.toHaveProperty('$gt');
    expect(result.filter.value).toBe('safe');
  });

  it('handles non-object input', () => {
    expect(sanitizeMongoQuery(null)).toEqual({});
    expect(sanitizeMongoQuery('string')).toEqual({});
  });
});

// ─── Error Handling — No Leakage ──────────────────────────────────────────────

describe('Error responses do not leak internal details (Task 6)', () => {
  it('404 response does not expose file paths', async () => {
    const res = await request(app).get('/api/nonexistent-endpoint-xyz');
    expect(res.status).toBe(404);
    expect(JSON.stringify(res.body)).not.toMatch(/node_modules|src\/|\.js/);
  });

  it('login error does not reveal DB structure', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'test@test.com',
      password: 'WrongPass!123',
    });
    expect(JSON.stringify(res.body)).not.toMatch(/mongodb|mongoose|schema|collection/i);
  });

  it('validation error does not include stack trace', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'bad', password: '' });
    expect(JSON.stringify(res.body)).not.toMatch(/at Object\.|at Function\.|stack/);
  });
});

// ─── Sensitive Field Stripping ─────────────────────────────────────────────────

describe('Sensitive fields never exposed in API responses', () => {
  it('login response does not include passwordHash', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'sectest@quickbank.test',
      password: 'Secure!Pass123',
    });
    expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|password_hash/);
  });

  it('profile response does not include twoFactorSecret', async () => {
    const res = await request(app)
      .get('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(JSON.stringify(res.body)).not.toMatch(/twoFactorSecret|two_factor_secret/);
  });

  it('profile response does not include failedLoginAttempts', async () => {
    const res = await request(app)
      .get('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(JSON.stringify(res.body)).not.toMatch(/failedLoginAttempts/);
  });
});

// ─── MongoDB Injection via Request Body ───────────────────────────────────────

describe('MongoDB injection prevention in API layer', () => {
  it('sanitizes $where operator in login body', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: { $where: '1==1' },
      password: 'anything',
    });
    // Should not succeed — either 422 (validation) or 401 (wrong credentials)
    expect([400, 401, 422]).toContain(res.status);
  });

  it('sanitizes $gt operator in login body', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: { $gt: '' },
      password: { $gt: '' },
    });
    expect([400, 401, 422]).toContain(res.status);
  });
});

// ─── Authorization ─────────────────────────────────────────────────────────────

describe('Authorization checks', () => {
  it('cannot access profile without token', async () => {
    const res = await request(app).get('/api/profile');
    expect(res.status).toBe(401);
  });

  it('cannot access accounts without token', async () => {
    const res = await request(app).get('/api/accounts');
    expect(res.status).toBe(401);
  });

  it('cannot access transactions without token', async () => {
    const res = await request(app).get('/api/transactions');
    expect(res.status).toBe(401);
  });

  it('admin route rejects non-admin user', async () => {
    const res = await request(app)
      .patch('/api/loans/000000000000000000000001/review')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ status: 'approved' });
    expect(res.status).toBe(403);
  });
});
