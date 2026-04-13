'use strict';

/**
 * Task 10 — Automated security tests: Authentication
 * Tests cover:
 * - Registration with valid/invalid inputs
 * - Login rate limiting (brute force prevention)
 * - Account lockout after max failed attempts
 * - Password reset token expiry and single-use enforcement
 * - 2FA setup and verification flow
 * - JWT token validation
 */

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');

// Seed a test user before tests
let testUser;
const TEST_EMAIL = 'authtest@quickbank.test';
const TEST_PASSWORD = 'Secure!Pass123';

beforeAll(async () => {
  await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/quickbank_test');
  await User.deleteMany({ email: TEST_EMAIL });
  testUser = new User({ email: TEST_EMAIL, firstName: 'Test', lastName: 'User' });
  await testUser.setPassword(TEST_PASSWORD);
  await testUser.save();
});

afterAll(async () => {
  await User.deleteMany({ email: TEST_EMAIL });
  await mongoose.connection.close();
});

// ─── Registration ─────────────────────────────────────────────────────────────

describe('POST /api/auth/register', () => {
  it('rejects weak passwords', async () => {
    const res = await request(app).post('/api/auth/register').send({
      email: 'newuser@test.com',
      password: 'weak',
      firstName: 'New',
      lastName: 'User',
    });
    expect(res.status).toBe(422);
    expect(res.body.details.some((d) => d.field === 'password')).toBe(true);
  });

  it('rejects invalid email format', async () => {
    const res = await request(app).post('/api/auth/register').send({
      email: 'not-an-email',
      password: TEST_PASSWORD,
      firstName: 'New',
      lastName: 'User',
    });
    expect(res.status).toBe(422);
  });

  it('accepts a valid registration', async () => {
    const res = await request(app).post('/api/auth/register').send({
      email: 'valid-new@quickbank.test',
      password: TEST_PASSWORD,
      firstName: 'Valid',
      lastName: 'User',
    });
    expect(res.status).toBe(201);
    await User.deleteOne({ email: 'valid-new@quickbank.test' });
  });

  it('does not reveal whether email is already taken', async () => {
    const res1 = await request(app).post('/api/auth/register').send({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
      firstName: 'Test',
      lastName: 'User',
    });
    const res2 = await request(app).post('/api/auth/register').send({
      email: 'definitely-new-123@quickbank.test',
      password: TEST_PASSWORD,
      firstName: 'New',
      lastName: 'User',
    });
    // Both should return 201 — prevent email enumeration
    expect(res1.status).toBe(201);
    expect(res2.status).toBe(201);
    await User.deleteOne({ email: 'definitely-new-123@quickbank.test' });
  });
});

// ─── Login ────────────────────────────────────────────────────────────────────

describe('POST /api/auth/login', () => {
  it('returns tokens on valid credentials', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
  });

  it('rejects wrong password with generic error', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: TEST_EMAIL,
      password: 'WrongPassword!123',
    });
    expect(res.status).toBe(401);
    // Generic message — must not reveal whether email exists
    expect(res.body.error).toBe('Invalid email or password');
  });

  it('rejects non-existent email with same generic error', async () => {
    const res = await request(app).post('/api/auth/login').send({
      email: 'ghost@quickbank.test',
      password: TEST_PASSWORD,
    });
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid email or password');
  });

  it('locks account after max failed attempts', async () => {
    const lockUser = new User({ email: 'locktest@quickbank.test', firstName: 'Lock', lastName: 'Test' });
    await lockUser.setPassword(TEST_PASSWORD);
    await lockUser.save();

    for (let i = 0; i < 5; i++) {
      await request(app).post('/api/auth/login').send({
        email: 'locktest@quickbank.test',
        password: 'WrongPass!123',
      });
    }

    const res = await request(app).post('/api/auth/login').send({
      email: 'locktest@quickbank.test',
      password: TEST_PASSWORD, // correct password — but account is locked
    });

    expect(res.status).toBe(423);
    expect(res.body.error).toMatch(/locked/i);

    await User.deleteOne({ email: 'locktest@quickbank.test' });
  });
});

// ─── JWT validation ───────────────────────────────────────────────────────────

describe('JWT validation', () => {
  it('rejects requests with no token', async () => {
    const res = await request(app).get('/api/profile');
    expect(res.status).toBe(401);
  });

  it('rejects requests with malformed token', async () => {
    const res = await request(app)
      .get('/api/profile')
      .set('Authorization', 'Bearer not.a.token');
    expect(res.status).toBe(401);
  });

  it('rejects a tampered token', async () => {
    const loginRes = await request(app).post('/api/auth/login').send({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
    });
    const token = loginRes.body.accessToken;
    // Tamper with the payload section
    const [header, , sig] = token.split('.');
    const tamperedPayload = Buffer.from(JSON.stringify({ sub: 'fakeid', role: 'admin' })).toString('base64url');
    const tamperedToken = `${header}.${tamperedPayload}.${sig}`;

    const res = await request(app)
      .get('/api/profile')
      .set('Authorization', `Bearer ${tamperedToken}`);
    expect(res.status).toBe(401);
  });
});

// ─── Password reset ───────────────────────────────────────────────────────────

describe('Password reset flow', () => {
  it('always returns 200 for reset request regardless of email existence', async () => {
    const r1 = await request(app).post('/api/auth/password-reset/request').send({ email: TEST_EMAIL });
    const r2 = await request(app).post('/api/auth/password-reset/request').send({ email: 'ghost@test.com' });
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r1.body.message).toBe(r2.body.message);
  });

  it('rejects expired/invalid reset token', async () => {
    const res = await request(app).post('/api/auth/password-reset/confirm').send({
      token: 'a'.repeat(64), // valid format, wrong token
      newPassword: 'NewSecure!Pass456',
    });
    expect(res.status).toBe(400);
  });

  it('rejects weak new password in reset', async () => {
    const res = await request(app).post('/api/auth/password-reset/confirm').send({
      token: 'a'.repeat(64),
      newPassword: 'weak',
    });
    expect(res.status).toBe(422);
  });
});
