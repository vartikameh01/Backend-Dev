'use strict';

/**
 * sanitizers.js
 * Task 2: Input sanitization utilities.
 * - HTML context: uses sanitize-html (allow-list)
 * - Plain text context: strip all tags
 * - Medical notes: preserve medical terminology but neutralise XSS vectors
 */

const sanitizeHtml = require('sanitize-html');

// ─── Allow-list for doctor notes / medical records ───────────────────────────
// Medical staff may use bold, italic, lists, and basic formatting for notes.
// NO script, iframe, object, embed, form, or event handlers allowed.
const MEDICAL_NOTES_ALLOWED = {
  allowedTags: ['b', 'i', 'em', 'strong', 'ul', 'ol', 'li', 'p', 'br', 'span'],
  allowedAttributes: {
    span: ['class'],
    p: ['class'],
  },
  allowedClasses: {},
  // Disallow all schemes except http/https for any href that might slip through
  allowedSchemes: ['http', 'https'],
  disallowedTagsMode: 'discard',
  allowProtocolRelative: false,
};

// ─── Exports ─────────────────────────────────────────────────────────────────

/**
 * sanitizePlainText
 * Strips ALL HTML tags. Use for names, IDs, search terms, etc.
 */
function sanitizePlainText(input) {
  if (typeof input !== 'string') return input;
  return sanitizeHtml(input, { allowedTags: [], allowedAttributes: {} }).trim();
}

/**
 * sanitizeMedicalText
 * Preserves safe formatting tags but removes all script vectors.
 * Use for medical history, symptoms, and other free-text medical fields.
 */
function sanitizeMedicalText(input) {
  if (typeof input !== 'string') return input;
  return sanitizeHtml(input, MEDICAL_NOTES_ALLOWED).trim();
}

/**
 * sanitizeDoctorNotes
 * Same policy as sanitizeMedicalText — used for prescription and doctor notes.
 */
function sanitizeDoctorNotes(input) {
  return sanitizeMedicalText(input);
}

/**
 * sanitizeSearchQuery
 * Strips tags and removes MongoDB operator characters ($ { }).
 * Prevents both XSS and NoSQL injection via search.
 */
function sanitizeSearchQuery(input) {
  if (typeof input !== 'string') return input;
  const stripped = sanitizePlainText(input);
  // Remove MongoDB operator characters
  return stripped.replace(/[${}]/g, '').trim();
}

/**
 * sanitizeObject
 * Recursively apply sanitizePlainText to all string values in a plain object.
 * Useful for sanitising entire request bodies at once.
 */
function sanitizeObject(obj) {
  if (Array.isArray(obj)) return obj.map(sanitizeObject);
  if (obj !== null && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k, sanitizeObject(v)])
    );
  }
  if (typeof obj === 'string') return sanitizePlainText(obj);
  return obj;
}

module.exports = {
  sanitizePlainText,
  sanitizeMedicalText,
  sanitizeDoctorNotes,
  sanitizeSearchQuery,
  sanitizeObject,
};
