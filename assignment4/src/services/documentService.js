'use strict';

/**
 * documentService.js
 * Task 3: Secure medical document handling.
 * - Format validation (magic bytes, not just extension)
 * - File size limits
 * - Encrypted storage (AES-256-GCM on disk)
 * - Access-logged retrieval
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { encrypt, decrypt } = require('./encryptionService');

// ─── Allowed MIME types and their magic byte signatures ──────────────────────
const ALLOWED_TYPES = {
  'application/pdf': [
    [0x25, 0x50, 0x44, 0x46], // %PDF
  ],
  'image/jpeg': [
    [0xFF, 0xD8, 0xFF],
  ],
  'image/png': [
    [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
  ],
  // DICOM files start with a 128-byte preamble + "DICM" at offset 128
  'application/dicom': null, // checked separately below
};

const MAX_FILE_SIZE_BYTES = (parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 10) * 1024 * 1024;
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || 'uploads/secure');

// Ensure the upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true, mode: 0o700 });
}

/**
 * validateMagicBytes
 * Reads the first 132 bytes of the file buffer and checks against known signatures.
 * @returns {{ valid: boolean, detectedType: string|null }}
 */
function validateMagicBytes(buffer) {
  if (!buffer || buffer.length < 8) return { valid: false, detectedType: null };

  // PDF
  if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
    return { valid: true, detectedType: 'application/pdf' };
  }
  // JPEG
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return { valid: true, detectedType: 'image/jpeg' };
  }
  // PNG
  if (
    buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47 &&
    buffer[4] === 0x0D && buffer[5] === 0x0A && buffer[6] === 0x1A && buffer[7] === 0x0A
  ) {
    return { valid: true, detectedType: 'image/png' };
  }
  // DICOM: 128-byte preamble + "DICM" at offset 128
  if (buffer.length >= 132) {
    const dicm = buffer.slice(128, 132).toString('ascii');
    if (dicm === 'DICM') {
      return { valid: true, detectedType: 'application/dicom' };
    }
  }

  return { valid: false, detectedType: null };
}

/**
 * validateAndStoreDocument
 * Validates the uploaded file buffer (magic bytes, size), then stores it
 * AES-256-GCM encrypted on disk with a random filename.
 *
 * @param {Buffer} fileBuffer  - raw file bytes from multer memoryStorage
 * @param {string} originalName - original filename from client
 * @param {string} claimedMime  - MIME type claimed by client
 * @returns {{ storedName: string, mimeType: string, sizeBytes: number }}
 */
function validateAndStoreDocument(fileBuffer, originalName, claimedMime) {
  // Size check
  if (fileBuffer.length > MAX_FILE_SIZE_BYTES) {
    const err = new Error(`File exceeds maximum size of ${process.env.MAX_FILE_SIZE_MB || 10} MB`);
    err.status = 413;
    throw err;
  }

  // Magic-byte validation — never trust the client-supplied MIME type
  const { valid, detectedType } = validateMagicBytes(fileBuffer);
  if (!valid) {
    const err = new Error('File type not allowed. Accepted formats: PDF, JPEG, PNG, DICOM');
    err.status = 415;
    throw err;
  }

  // Reject if the client-claimed MIME doesn't match detected type
  if (claimedMime && detectedType && claimedMime !== detectedType) {
    const err = new Error('File type mismatch between declared and actual content');
    err.status = 415;
    throw err;
  }

  // Sanitise file name — reject path traversal, keep only the base name
  const safeName = path.basename(originalName).replace(/[^a-zA-Z0-9._\-]/g, '_');

  // Generate a random UUID-based stored filename; never expose original on disk
  const storedName = `${crypto.randomUUID()}_${Date.now()}`;
  const storedPath = path.join(UPLOAD_DIR, storedName);

  // Encrypt the file content before writing to disk (Task 6: data at rest)
  const encryptedContent = encrypt(fileBuffer.toString('base64'));
  fs.writeFileSync(storedPath, encryptedContent, { mode: 0o600 });

  return {
    storedName,
    originalName: safeName,
    mimeType: detectedType,
    sizeBytes: fileBuffer.length,
  };
}

/**
 * retrieveDocument
 * Decrypts and returns the file buffer for a stored document.
 * Call auditService.log(DOCUMENT_VIEW) BEFORE calling this.
 */
function retrieveDocument(storedName) {
  // Prevent path traversal: validate storedName is a bare filename only
  const safe = path.basename(storedName);
  if (safe !== storedName || storedName.includes('..') || storedName.includes('/')) {
    const err = new Error('Invalid document identifier');
    err.status = 400;
    throw err;
  }

  const storedPath = path.join(UPLOAD_DIR, safe);
  if (!fs.existsSync(storedPath)) {
    const err = new Error('Document not found');
    err.status = 404;
    throw err;
  }

  const encryptedContent = fs.readFileSync(storedPath, 'utf8');
  const decryptedBase64 = decrypt(encryptedContent);
  return Buffer.from(decryptedBase64, 'base64');
}

/**
 * deleteDocument
 * Securely deletes a stored document from disk.
 */
function deleteDocument(storedName) {
  const safe = path.basename(storedName);
  const storedPath = path.join(UPLOAD_DIR, safe);
  if (fs.existsSync(storedPath)) {
    fs.unlinkSync(storedPath);
  }
}

module.exports = {
  validateMagicBytes,
  validateAndStoreDocument,
  retrieveDocument,
  deleteDocument,
  MAX_FILE_SIZE_BYTES,
  ALLOWED_TYPES,
};
