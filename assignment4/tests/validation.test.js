'use strict';

/**
 * validation.test.js
 * Tests for: input validation and sanitization (Task 2).
 * Covers patient personal info, medical text, dates, SSN, phone, email.
 */

process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.NODE_ENV = 'test';

const { validationResult } = require('express-validator');
const {
  validateEmail,
  validateSSN,
  validatePhone,
  validateDOB,
  validateAppointmentDate,
  validateMedicalText,
  validateSearchQuery,
} = require('../src/utils/validators');

const {
  sanitizePlainText,
  sanitizeMedicalText,
  sanitizeSearchQuery,
  sanitizeObject,
} = require('../src/utils/sanitizers');

// ─── Helper ───────────────────────────────────────────────────────────────────
async function runChain(chain, reqPartial) {
  const req = { body: {}, query: {}, params: {}, headers: {}, ...reqPartial };
  await chain.run(req);
  return validationResult(req);
}

// ─── Email Validation ─────────────────────────────────────────────────────────
describe('Email Validation (Task 2)', () => {
  test('accepts valid email', async () => {
    const r = await runChain(validateEmail(), { body: { email: 'patient@hospital.org' } });
    expect(r.isEmpty()).toBe(true);
  });

  test('rejects email without @', async () => {
    const r = await runChain(validateEmail(), { body: { email: 'notanemail' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects email without domain', async () => {
    const r = await runChain(validateEmail(), { body: { email: 'user@' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects empty email', async () => {
    const r = await runChain(validateEmail(), { body: { email: '' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects email over 254 characters', async () => {
    const r = await runChain(validateEmail(), { body: { email: 'a'.repeat(244) + '@test.com' } });
    expect(r.isEmpty()).toBe(false);
  });
});

// ─── SSN Validation ───────────────────────────────────────────────────────────
describe('SSN Validation (Task 2)', () => {
  test('accepts valid SSN', async () => {
    const r = await runChain(validateSSN(), { body: { ssn: '123-45-6789' } });
    expect(r.isEmpty()).toBe(true);
  });

  test('rejects SSN with area 000', async () => {
    const r = await runChain(validateSSN(), { body: { ssn: '000-45-6789' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects SSN with area 666', async () => {
    const r = await runChain(validateSSN(), { body: { ssn: '666-45-6789' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects SSN with area 900-999', async () => {
    const r = await runChain(validateSSN(), { body: { ssn: '900-45-6789' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects SSN without dashes', async () => {
    const r = await runChain(validateSSN(), { body: { ssn: '123456789' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('accepts SSN field being absent (optional)', async () => {
    const r = await runChain(validateSSN(), { body: {} });
    expect(r.isEmpty()).toBe(true);
  });
});

// ─── Phone Validation ─────────────────────────────────────────────────────────
describe('Phone Validation (Task 2)', () => {
  test('accepts US phone (XXX) XXX-XXXX', async () => {
    const r = await runChain(validatePhone(), { body: { phone: '(800) 555-1234' } });
    expect(r.isEmpty()).toBe(true);
  });

  test('accepts 10-digit phone', async () => {
    const r = await runChain(validatePhone(), { body: { phone: '8005551234' } });
    expect(r.isEmpty()).toBe(true);
  });

  test('rejects phone with letters', async () => {
    const r = await runChain(validatePhone(), { body: { phone: 'abc-def-ghij' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('accepts absent phone (optional)', async () => {
    const r = await runChain(validatePhone(), { body: {} });
    expect(r.isEmpty()).toBe(true);
  });
});

// ─── Date of Birth Validation ─────────────────────────────────────────────────
describe('Date of Birth Validation (Task 2)', () => {
  test('rejects future date', async () => {
    const future = new Date(Date.now() + 86400000).toISOString().split('T')[0];
    const r = await runChain(validateDOB(), { body: { dateOfBirth: future } });
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects date before 1900', async () => {
    const r = await runChain(validateDOB(), { body: { dateOfBirth: '1899-12-31' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('accepts valid past date', async () => {
    const r = await runChain(validateDOB(), { body: { dateOfBirth: '1985-06-15' } });
    expect(r.isEmpty()).toBe(true);
  });

  test('rejects non-ISO string', async () => {
    const r = await runChain(validateDOB(), { body: { dateOfBirth: 'June 5th 1990' } });
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects arbitrary string that causes crashes', async () => {
    const r = await runChain(validateDOB(), { body: { dateOfBirth: 'DROP TABLE users' } });
    expect(r.isEmpty()).toBe(false);
  });
});

// ─── Appointment Date Validation ──────────────────────────────────────────────
describe('Appointment Date Validation (Task 2)', () => {
  test('rejects past appointment date', async () => {
    const past = new Date(Date.now() - 86400000).toISOString();
    const r = await runChain(validateAppointmentDate(), { body: { appointmentDate: past } });
    expect(r.isEmpty()).toBe(false);
  });

  test('accepts future appointment date', async () => {
    const future = new Date(Date.now() + 7 * 86400000).toISOString();
    const r = await runChain(validateAppointmentDate(), { body: { appointmentDate: future } });
    expect(r.isEmpty()).toBe(true);
  });

  test('rejects date 3 years in future', async () => {
    const farFuture = new Date();
    farFuture.setFullYear(farFuture.getFullYear() + 3);
    const r = await runChain(validateAppointmentDate(), { body: { appointmentDate: farFuture.toISOString() } });
    expect(r.isEmpty()).toBe(false);
  });
});

// ─── Medical Text Sanitization (Task 2: XSS prevention) ──────────────────────
describe('Medical Text Sanitization (Task 2 — XSS prevention)', () => {
  test('strips <script> tags', () => {
    const input = 'Patient has fever.<script>alert(1)</script>';
    expect(sanitizeMedicalText(input)).not.toContain('<script>');
    expect(sanitizeMedicalText(input)).toContain('Patient has fever');
  });

  test('strips <iframe> tags', () => {
    const input = 'Notes: <iframe src="evil.com"></iframe> stable';
    expect(sanitizeMedicalText(input)).not.toContain('<iframe');
  });

  test('strips onclick event handlers', () => {
    const input = '<b onclick="steal()">Note</b>';
    expect(sanitizeMedicalText(input)).not.toContain('onclick');
  });

  test('preserves allowed formatting tags', () => {
    const input = '<b>Diagnosis:</b> <em>hypertension</em>';
    const result = sanitizeMedicalText(input);
    expect(result).toContain('<b>');
    expect(result).toContain('<em>');
  });

  test('preserves medical terminology', () => {
    const input = 'Rx: metformin 500mg TID × 30 days. BP 130/85 mmHg.';
    expect(sanitizeMedicalText(input)).toContain('metformin');
  });

  test('strips javascript: URIs', () => {
    const input = '<a href="javascript:alert(1)">click</a>';
    expect(sanitizeMedicalText(input)).not.toContain('javascript:');
  });
});

// ─── Plain Text Sanitization ──────────────────────────────────────────────────
describe('Plain Text Sanitization (Task 2)', () => {
  test('strips all HTML tags', () => {
    expect(sanitizePlainText('<b>Hello</b>')).toBe('Hello');
  });

  test('strips script injection', () => {
    expect(sanitizePlainText('<script>xss</script>')).toBe('');
  });

  test('preserves regular text', () => {
    expect(sanitizePlainText('John O\'Brien')).toBe('John O\'Brien');
  });

  test('sanitizeObject handles nested objects', () => {
    const input = { name: '<b>Alice</b>', address: { city: '<script>bad</script>Town' } };
    const result = sanitizeObject(input);
    expect(result.name).toBe('Alice');
    expect(result.address.city).toBe('Town');
  });
});

// ─── Search Query Sanitization (Task 4: injection prevention) ─────────────────
describe('Search Query Sanitization (Task 2 + 4)', () => {
  test('removes MongoDB $ operator from search', () => {
    expect(sanitizeSearchQuery('{ $gt: "" }')).not.toContain('$');
  });

  test('removes curly braces from search', () => {
    expect(sanitizeSearchQuery('{injection}')).not.toContain('{');
  });

  test('preserves normal search terms', () => {
    expect(sanitizeSearchQuery('cardiology')).toBe('cardiology');
  });

  test('validator rejects $ characters in query', async () => {
    const r = await runChain(validateSearchQuery(), { query: { q: '{ $gt: "" }' } });
    expect(r.isEmpty()).toBe(false);
  });
});
