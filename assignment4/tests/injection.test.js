'use strict';

/**
 * injection.test.js
 * Tests for: MongoDB injection prevention (Task 4) and input sanitization.
 * Verifies that operator-prefix characters are stripped/rejected at every layer.
 */

process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.NODE_ENV = 'test';

const { sanitizeSearchQuery, sanitizePlainText } = require('../src/utils/sanitizers');
const { validateSearchQuery } = require('../src/utils/validators');
const { validationResult } = require('express-validator');

async function runValidatorOnQuery(value) {
  const req = { body: {}, query: { q: value }, params: {}, headers: {} };
  await validateSearchQuery().run(req);
  return validationResult(req);
}

// ─── express-mongo-sanitize behavior tests ────────────────────────────────────
// We simulate what the middleware does by verifying our sanitizers strip operators.
describe('MongoDB Operator Injection Prevention (Task 4)', () => {

  describe('Search query sanitizer', () => {
    test('strips $ operator prefix', () => {
      expect(sanitizeSearchQuery('$gt')).toBe('gt');
    });

    test('strips $where operator', () => {
      expect(sanitizeSearchQuery('{ $where: "function(){return true}" }')).not.toContain('$where');
    });

    test('strips nested operator injection', () => {
      const payload = '{"$gt": ""}';
      expect(sanitizeSearchQuery(payload)).not.toContain('$');
    });

    test('strips curly braces', () => {
      expect(sanitizeSearchQuery('{admin}')).not.toContain('{');
    });

    test('preserves legitimate medical search terms', () => {
      expect(sanitizeSearchQuery('cardiology')).toBe('cardiology');
      expect(sanitizeSearchQuery('John Smith')).toBe('John Smith');
    });

    test('preserves hyphens in names', () => {
      expect(sanitizeSearchQuery('Mary-Jane')).toBe('Mary-Jane');
    });
  });

  describe('Search query validator', () => {
    test('rejects $ character in query param', async () => {
      const r = await runValidatorOnQuery('{ $gt: "" }');
      expect(r.isEmpty()).toBe(false);
    });

    test('rejects { character in query param', async () => {
      const r = await runValidatorOnQuery('{inject}');
      expect(r.isEmpty()).toBe(false);
    });

    test('accepts normal search string', async () => {
      const r = await runValidatorOnQuery('cardiology specialist');
      expect(r.isEmpty()).toBe(true);
    });

    test('accepts empty query (optional field)', async () => {
      const req = { body: {}, query: {}, params: {}, headers: {} };
      await validateSearchQuery().run(req);
      const r = validationResult(req);
      expect(r.isEmpty()).toBe(true);
    });

    test('rejects query over 100 characters', async () => {
      const r = await runValidatorOnQuery('a'.repeat(101));
      expect(r.isEmpty()).toBe(false);
    });
  });

  describe('Plain text sanitizer (cross-cutting)', () => {
    test('strips <script> from plain text', () => {
      expect(sanitizePlainText('<script>alert(1)</script>')).toBe('');
    });

    test('strips HTML tags from patient name field', () => {
      expect(sanitizePlainText('<b>John</b> <img src=x onerror=alert(1)>')).toBe('John');
    });

    test('preserves apostrophes in names', () => {
      expect(sanitizePlainText("O'Brien")).toBe("O'Brien");
    });
  });
});

// ─── Date injection prevention ────────────────────────────────────────────────
describe('Date Field Injection Prevention (Task 2 + 4)', () => {
  const { validateDOB, validateAppointmentDate } = require('../src/utils/validators');

  async function runDOB(val) {
    const req = { body: { dateOfBirth: val }, query: {}, params: {}, headers: {} };
    await validateDOB().run(req);
    return validationResult(req);
  }

  async function runApptDate(val) {
    const req = { body: { appointmentDate: val }, query: {}, params: {}, headers: {} };
    await validateAppointmentDate().run(req);
    return validationResult(req);
  }

  test('rejects { $gt: "" } as date of birth', async () => {
    const r = await runDOB('{ "$gt": "" }');
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects "any string" as appointment date', async () => {
    const r = await runApptDate('DROP TABLE appointments');
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects null-byte injection', async () => {
    const r = await runDOB('\x001985-06-15');
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects UNIX timestamp string as date', async () => {
    const r = await runApptDate('1713916800000'); // a number, not ISO8601
    expect(r.isEmpty()).toBe(false);
  });
});

// ─── XSS in medical text validator ────────────────────────────────────────────
describe('XSS Prevention in Medical Fields (Task 2)', () => {
  const { validateMedicalText } = require('../src/utils/validators');

  async function runMedical(val) {
    const req = { body: { notes: val }, query: {}, params: {}, headers: {} };
    await validateMedicalText('notes').run(req);
    return validationResult(req);
  }

  test('rejects <script> tag in notes', async () => {
    const r = await runMedical('<script>alert(1)</script> patient notes');
    expect(r.isEmpty()).toBe(false);
  });

  test('rejects javascript: URI in notes', async () => {
    const r = await runMedical('see javascript:void(0) for details');
    expect(r.isEmpty()).toBe(false);
  });

  test('accepts plain medical note', async () => {
    const r = await runMedical('Patient reports chest pain 7/10 with dyspnea on exertion.');
    expect(r.isEmpty()).toBe(true);
  });

  test('rejects notes over 5000 characters', async () => {
    const r = await runMedical('x'.repeat(5001));
    expect(r.isEmpty()).toBe(false);
  });
});
