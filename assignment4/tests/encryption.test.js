'use strict';

/**
 * encryption.test.js
 * Tests for: AES-256-GCM encryption (Task 6) and document validation (Task 3).
 */

process.env.ENCRYPTION_KEY = 'b'.repeat(64);
process.env.NODE_ENV = 'test';

const { encrypt, decrypt, hashForSearch } = require('../src/services/encryptionService');
const { validateMagicBytes, MAX_FILE_SIZE_BYTES } = require('../src/services/documentService');

// ─── Encryption / Decryption ──────────────────────────────────────────────────
describe('AES-256-GCM Encryption (Task 6)', () => {
  test('encrypt produces a non-empty string', () => {
    const result = encrypt('Hello PHI');
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  test('encrypted value contains iv:authTag:ciphertext segments', () => {
    const result = encrypt('test');
    const parts = result.split(':');
    expect(parts.length).toBe(3);
  });

  test('decrypt recovers original plaintext', () => {
    const original = 'SSN-123-45-6789';
    expect(decrypt(encrypt(original))).toBe(original);
  });

  test('two encryptions of the same value produce different ciphertexts (random IV)', () => {
    const a = encrypt('same value');
    const b = encrypt('same value');
    expect(a).not.toBe(b);
  });

  test('decrypt throws on tampered ciphertext', () => {
    const enc = encrypt('secret');
    const [iv, tag, ct] = enc.split(':');
    const tampered = `${iv}:${tag}:${Buffer.from('corrupted').toString('base64')}`;
    expect(() => decrypt(tampered)).toThrow();
  });

  test('decrypt throws on malformed input', () => {
    expect(() => decrypt('notvalidformat')).toThrow('Invalid encrypted value format');
  });

  test('encrypt handles empty string', () => {
    const enc = encrypt('');
    expect(decrypt(enc)).toBe('');
  });

  test('encrypt handles unicode / medical symbols', () => {
    const input = 'μg/mL ≥ 0.5 — diagnosis: hypertension';
    expect(decrypt(encrypt(input))).toBe(input);
  });

  test('null passthrough for null values', () => {
    expect(encrypt(null)).toBeNull();
    expect(decrypt(null)).toBeNull();
  });
});

// ─── HMAC Hash for Search ─────────────────────────────────────────────────────
describe('hashForSearch (Task 6 — equality lookup on encrypted fields)', () => {
  test('same value produces same hash', () => {
    expect(hashForSearch('123-45-6789')).toBe(hashForSearch('123-45-6789'));
  });

  test('different values produce different hashes', () => {
    expect(hashForSearch('123-45-6789')).not.toBe(hashForSearch('987-65-4321'));
  });

  test('hash is case-insensitive and trimmed', () => {
    expect(hashForSearch('  ABC  ')).toBe(hashForSearch('abc'));
  });

  test('returns null for null/undefined', () => {
    expect(hashForSearch(null)).toBeNull();
    expect(hashForSearch('')).toBeNull();
  });
});

// ─── Document Magic Byte Validation (Task 3) ──────────────────────────────────
describe('Document Magic Byte Validation (Task 3)', () => {
  // Build minimal valid headers for each file type
  const pdfHeader = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34]); // %PDF-1.4
  const jpegHeader = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46]);
  const pngHeader  = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const dicomHeader = Buffer.concat([Buffer.alloc(128, 0), Buffer.from('DICM')]);
  const fakeExe = Buffer.from([0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // MZ (EXE)

  test('accepts PDF magic bytes', () => {
    const { valid, detectedType } = validateMagicBytes(pdfHeader);
    expect(valid).toBe(true);
    expect(detectedType).toBe('application/pdf');
  });

  test('accepts JPEG magic bytes', () => {
    const { valid, detectedType } = validateMagicBytes(jpegHeader);
    expect(valid).toBe(true);
    expect(detectedType).toBe('image/jpeg');
  });

  test('accepts PNG magic bytes', () => {
    const { valid, detectedType } = validateMagicBytes(pngHeader);
    expect(valid).toBe(true);
    expect(detectedType).toBe('image/png');
  });

  test('accepts DICOM magic bytes (DICM at offset 128)', () => {
    const { valid, detectedType } = validateMagicBytes(dicomHeader);
    expect(valid).toBe(true);
    expect(detectedType).toBe('application/dicom');
  });

  test('rejects EXE file disguised as PDF', () => {
    const { valid } = validateMagicBytes(fakeExe);
    expect(valid).toBe(false);
  });

  test('rejects empty buffer', () => {
    const { valid } = validateMagicBytes(Buffer.alloc(0));
    expect(valid).toBe(false);
  });

  test('rejects null', () => {
    const { valid } = validateMagicBytes(null);
    expect(valid).toBe(false);
  });

  test('rejects PHP webshell bytes', () => {
    const php = Buffer.from('<?php system($_GET["cmd"]); ?>');
    const { valid } = validateMagicBytes(php);
    expect(valid).toBe(false);
  });
});

// ─── File Size Limit ──────────────────────────────────────────────────────────
describe('File Size Limit (Task 3)', () => {
  test('MAX_FILE_SIZE_BYTES is a positive number', () => {
    expect(MAX_FILE_SIZE_BYTES).toBeGreaterThan(0);
  });

  test('default size limit is 10 MB', () => {
    expect(MAX_FILE_SIZE_BYTES).toBeLessThanOrEqual(10 * 1024 * 1024);
  });
});
