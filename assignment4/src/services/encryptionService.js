'use strict';

/**
 * encryptionService.js
 * Task 6: AES-256-GCM encryption for data at rest.
 * Encrypts/decrypts PHI fields (SSN, medical history, insurance details).
 * GCM mode provides both confidentiality and integrity (authenticated encryption).
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = parseInt(process.env.ENCRYPTION_IV_LENGTH, 10) || 16;
const AUTH_TAG_LENGTH = 16; // GCM auth tag bytes

function getKey() {
  const hexKey = process.env.ENCRYPTION_KEY;
  if (!hexKey || hexKey.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  }
  return Buffer.from(hexKey, 'hex');
}

/**
 * encrypt
 * @param {string} plaintext — string to encrypt
 * @returns {string} base64-encoded "iv:authTag:ciphertext"
 */
function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined) return plaintext;
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Encode as three colon-separated base64 segments
  return [
    iv.toString('base64'),
    authTag.toString('base64'),
    encrypted.toString('base64'),
  ].join(':');
}

/**
 * decrypt
 * @param {string} encoded — value returned by encrypt()
 * @returns {string} original plaintext
 */
function decrypt(encoded) {
  if (encoded === null || encoded === undefined) return encoded;
  const key = getKey();
  const [ivB64, authTagB64, encryptedB64] = encoded.split(':');
  if (!ivB64 || !authTagB64 || !encryptedB64) {
    throw new Error('Invalid encrypted value format');
  }
  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(authTagB64, 'base64');
  const encryptedBuf = Buffer.from(encryptedB64, 'base64');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(encryptedBuf), decipher.final()]);
  return decrypted.toString('utf8');
}

/**
 * hashForSearch
 * One-way HMAC-SHA256 of a value — allows equality lookups on encrypted fields
 * (e.g., find patient by SSN) without storing the plaintext.
 */
function hashForSearch(value) {
  if (!value) return null;
  return crypto
    .createHmac('sha256', getKey())
    .update(String(value).toLowerCase().trim())
    .digest('hex');
}

module.exports = { encrypt, decrypt, hashForSearch };
