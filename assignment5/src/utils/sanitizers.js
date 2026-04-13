'use strict';

const sanitizeHtml = require('sanitize-html');
const xss = require('xss');

/**
 * sanitizeText
 * Strips all HTML tags — use for plain-text fields like names, descriptions.
 * Prevents stored XSS in email notifications and UI rendering.
 *
 * @param {string} input
 * @returns {string}
 */
function sanitizeText(input) {
  if (typeof input !== 'string') return '';
  return sanitizeHtml(input, { allowedTags: [], allowedAttributes: {} }).trim();
}

/**
 * sanitizeRichText
 * Allows a safe subset of HTML (b, i, u, p) — for user-facing descriptions.
 * More permissive than sanitizeText but still strips scripts and event handlers.
 *
 * @param {string} input
 * @returns {string}
 */
function sanitizeRichText(input) {
  if (typeof input !== 'string') return '';
  return sanitizeHtml(input, {
    allowedTags: ['b', 'i', 'u', 'p', 'br'],
    allowedAttributes: {},
  }).trim();
}

/**
 * sanitizeForEmail
 * Escapes HTML entities for safe inclusion inside email body text.
 * Fixes the vulnerability where unsanitized transaction descriptions caused XSS in emails.
 *
 * @param {string} input
 * @returns {string}
 */
function sanitizeForEmail(input) {
  if (typeof input !== 'string') return '';
  // Strip all HTML, then XSS-encode the result for belt-and-suspenders safety
  const stripped = sanitizeHtml(input, { allowedTags: [], allowedAttributes: {} });
  return xss(stripped);
}

/**
 * sanitizeAccountNumber
 * Validates and strips non-digit characters from account/routing numbers.
 * Returns null if the result doesn't match expected digit-only format.
 *
 * @param {string} input
 * @returns {string|null}
 */
function sanitizeAccountNumber(input) {
  if (typeof input !== 'string') return null;
  const digits = input.replace(/\D/g, '');
  // Account numbers: 8–17 digits; routing numbers: exactly 9
  if (digits.length < 8 || digits.length > 17) return null;
  return digits;
}

/**
 * sanitizeMongoQuery
 * Removes MongoDB operator keys ($) from untrusted objects to prevent NoSQL injection.
 * express-mongo-sanitize covers req.body/query/params, but this helper covers
 * manually constructed query objects.
 *
 * @param {object} obj
 * @returns {object}
 */
function sanitizeMongoQuery(obj) {
  if (typeof obj !== 'object' || obj === null) return {};
  const clean = {};
  for (const [key, value] of Object.entries(obj)) {
    if (key.startsWith('$')) continue; // drop MongoDB operators
    clean[key] = typeof value === 'object' ? sanitizeMongoQuery(value) : value;
  }
  return clean;
}

module.exports = {
  sanitizeText,
  sanitizeRichText,
  sanitizeForEmail,
  sanitizeAccountNumber,
  sanitizeMongoQuery,
};
