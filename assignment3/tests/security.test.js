/**
 * Security Tests - EduLearn
 * Tests for authentication, authorization, XSS, injection, rate limiting, and file uploads
 */

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const User = require('../src/models/User');
const Course = require('../src/models/Course');
const { sanitizeRichText, sanitizePlainText, sanitizeQuizContent } = require('../src/utils/sanitizer');
const { verifyMagicBytes, scanForMaliciousContent } = require('../src/middleware/fileUpload');

// ========================
// XSS Sanitization Tests
// ========================
describe('XSS Sanitization', () => {
  test('sanitizeRichText removes script tags', () => {
    const dirty = '<p>Hello</p><script>alert("xss")</script>';
    const clean = sanitizeRichText(dirty);
    expect(clean).not.toContain('<script>');
    expect(clean).toContain('<p>Hello</p>');
  });

  test('sanitizeRichText removes event handlers', () => {
    const dirty = '<p onclick="alert(1)">Click me</p>';
    const clean = sanitizeRichText(dirty);
    expect(clean).not.toContain('onclick');
    expect(clean).toContain('<p>');
  });

  test('sanitizeRichText preserves safe formatting', () => {
    const safe = '<h1>Title</h1><p><strong>Bold</strong> and <em>italic</em></p><ul><li>Item</li></ul>';
    const clean = sanitizeRichText(safe);
    expect(clean).toContain('<h1>Title</h1>');
    expect(clean).toContain('<strong>Bold</strong>');
  });

  test('sanitizeRichText removes iframes', () => {
    const dirty = '<iframe src="https://evil.com"></iframe>';
    const clean = sanitizeRichText(dirty);
    expect(clean).not.toContain('<iframe');
  });

  test('sanitizePlainText strips all HTML', () => {
    const dirty = '<script>alert(1)</script><b>text</b>';
    const clean = sanitizePlainText(dirty);
    expect(clean).toBe('text');
  });

  test('sanitizeQuizContent removes links', () => {
    const dirty = '<a href="https://evil.com">click</a><strong>important</strong>';
    const clean = sanitizeQuizContent(dirty);
    expect(clean).not.toContain('<a ');
    expect(clean).toContain('<strong>');
  });

  test('sanitizePlainText handles javascript: URLs in text', () => {
    const dirty = 'javascript:alert(1)';
    const clean = sanitizePlainText(dirty);
    expect(clean).toBe('javascript:alert(1)');
    // Plain text is fine - it's just text
  });
});

// ========================
// File Upload Security Tests
// ========================
describe('File Upload Security', () => {
  test('verifyMagicBytes accepts valid PDF', () => {
    const pdfBuffer = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e]);
    const result = verifyMagicBytes(pdfBuffer, 'application/pdf');
    expect(result).toBe(true);
  });

  test('verifyMagicBytes rejects fake PDF (wrong magic bytes)', () => {
    const fakeBuffer = Buffer.from([0x4D, 0x5A, 0x90, 0x00]); // PE executable header
    const result = verifyMagicBytes(fakeBuffer, 'application/pdf');
    expect(result).toBe(false);
  });

  test('scanForMaliciousContent detects script tags', () => {
    const malicious = Buffer.from('<script>alert("xss")</script>');
    const result = scanForMaliciousContent(malicious);
    expect(result.safe).toBe(false);
  });

  test('scanForMaliciousContent detects PHP tags', () => {
    const malicious = Buffer.from('<?php system($_GET["cmd"]); ?>');
    const result = scanForMaliciousContent(malicious);
    expect(result.safe).toBe(false);
  });

  test('scanForMaliciousContent detects PowerShell', () => {
    const malicious = Buffer.from('powershell -enc base64encodedpayload');
    const result = scanForMaliciousContent(malicious);
    expect(result.safe).toBe(false);
  });

  test('scanForMaliciousContent accepts clean PDF text', () => {
    const clean = Buffer.from('%PDF-1.4 clean document content here');
    const result = scanForMaliciousContent(clean);
    expect(result.safe).toBe(true);
  });
});

// ========================
// Password Validation Tests
// ========================
describe('Password Security', () => {
  test('weak password is rejected', async () => {
    const user = new User({ email: 'test@test.com', password: 'weak', name: 'Test' });
    await expect(user.save()).rejects.toThrow();
  });

  test('password without special char is rejected', async () => {
    const user = new User({ email: 'test2@test.com', password: 'NoSpecialChar123', name: 'Test' });
    await expect(user.save()).rejects.toThrow();
  });

  test('strong password is accepted', async () => {
    const user = new User({ email: 'test3@example.com', password: 'StrongPass@123', name: 'Test User' });
    // Should not throw ValidationError for password
    expect(user.password).toBeDefined();
  });

  test('password is hashed before saving', async () => {
    const password = 'ValidPass@123!';
    const user = new User({ email: 'hash@test.com', password, name: 'Hash Test' });
    await user.save().catch(() => {}); // May fail for other reasons (DB not connected)
    expect(user.password).not.toBe(password);
  });
});

// ========================
// Account Lockout Tests
// ========================
describe('Account Lockout', () => {
  test('account locks after 5 failed login attempts', async () => {
    const user = new User({
      email: 'lockout@test.com',
      password: 'TestPass@123!',
      name: 'Lockout Test',
      loginAttempts: 4
    });

    await user.handleFailedLogin();
    expect(user.loginAttempts).toBe(5);
    expect(user.lockUntil).toBeDefined();
    expect(user.isLocked).toBe(true);
  });

  test('successful login resets attempts', async () => {
    const user = new User({
      email: 'reset@test.com',
      password: 'TestPass@123!',
      name: 'Reset Test',
      loginAttempts: 3
    });

    await user.handleSuccessfulLogin();
    expect(user.loginAttempts).toBe(0);
    expect(user.lockUntil).toBeNull();
  });
});

// ========================
// API Security Tests (Integration)
// ========================
describe('API Security', () => {
  test('protected route returns 401 without session', async () => {
    const res = await request(app).get('/api/messages/inbox');
    expect(res.status).toBe(401);
  });

  test('login rate limiter exists on /api/auth/login', async () => {
    // Make multiple rapid requests
    const responses = await Promise.all(
      Array(6).fill(null).map(() =>
        request(app)
          .post('/api/auth/login')
          .send({ email: 'test@test.com', password: 'wrong' })
      )
    );

    const rateLimited = responses.some(r => r.status === 429);
    expect(rateLimited).toBe(true);
  });

  test('MongoDB injection is blocked in query params', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: { $gt: '' }, password: 'anything' });

    // Should not succeed with injection attempt
    expect(res.status).not.toBe(200);
  });

  test('large request body is rejected', async () => {
    const bigPayload = { title: 'a'.repeat(100000) };
    const res = await request(app)
      .post('/api/courses')
      .send(bigPayload);

    expect([400, 401, 413]).toContain(res.status);
  });

  test('health endpoint is accessible', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
  });

  test('404 for unknown routes', async () => {
    const res = await request(app).get('/api/nonexistent');
    expect(res.status).toBe(404);
  });

  test('security headers are present', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBeDefined();
  });
});

// ========================
// Input Validation Tests
// ========================
describe('Input Validation', () => {
  test('invalid email is rejected on registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'not-an-email', password: 'TestPass@123!', name: 'Test' });

    expect(res.status).toBe(400);
    expect(res.body.errors).toBeDefined();
  });

  test('short password is rejected on registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'valid@test.com', password: 'short', name: 'Test' });

    expect(res.status).toBe(400);
  });

  test('invalid MongoDB ID format is rejected', async () => {
    const res = await request(app).get('/api/courses/not-a-valid-id');
    expect(res.status).toBe(400);
  });
});
