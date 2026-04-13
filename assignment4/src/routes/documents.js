'use strict';

/**
 * documents.js (routes)
 * Task 3: Secure medical document upload, retrieval, and deletion.
 * - multer memoryStorage (never writes untrusted bytes to disk directly)
 * - validateAndStoreDocument validates magic bytes + encrypts
 * - All access is audit-logged
 * - Path traversal prevented in both upload and retrieval
 */

const express = require('express');
const router = express.Router();
const multer = require('multer');

const MedicalRecord = require('../models/MedicalRecord');
const { authenticate } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { sensitiveRateLimiter } = require('../middleware/rateLimiter');
const { handleValidationErrors } = require('../middleware/validate');
const { log, ACTIONS } = require('../services/auditService');
const { validateAndStoreDocument, retrieveDocument, deleteDocument, MAX_FILE_SIZE_BYTES } = require('../services/documentService');
const { validateMongoId } = require('../utils/validators');

// ─── Multer: store in memory, enforce size limit before processing ─────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['application/pdf', 'image/jpeg', 'image/png', 'application/dicom'];
    if (allowed.includes(file.mimetype)) return cb(null, true);
    cb(new Error('File type not allowed'));
  },
});

// ─── POST /documents/upload/:recordId ─────────────────────────────────────────
router.post(
  '/upload/:recordId',
  authenticate,
  requireRole('doctor', 'admin', 'nurse'),
  sensitiveRateLimiter,
  [validateMongoId('recordId')],
  handleValidationErrors,
  upload.single('document'),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: 'No file provided' });

      const record = await MedicalRecord.findOne({ _id: { $eq: req.params.recordId } });
      if (!record) return res.status(404).json({ error: 'Medical record not found' });

      // Task 3: Validate magic bytes + size + encrypt-to-disk
      const stored = validateAndStoreDocument(
        req.file.buffer,
        req.file.originalname,
        req.file.mimetype
      );

      record.documents.push({
        storedName:   stored.storedName,
        originalName: stored.originalName,
        mimeType:     stored.mimeType,
        sizeBytes:    stored.sizeBytes,
        uploadedBy:   req.user.id,
      });
      await record.save();

      await log({
        action: ACTIONS.DOCUMENT_UPLOAD,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.recordId,
        targetType: 'MedicalRecord',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: { mimeType: stored.mimeType, sizeBytes: stored.sizeBytes },
      });

      return res.status(201).json({
        message: 'Document uploaded',
        documentId: stored.storedName,
        mimeType: stored.mimeType,
      });
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ error: err.message || 'Upload failed' });
    }
  }
);

// ─── GET /documents/:recordId/:storedName ─────────────────────────────────────
router.get(
  '/:recordId/:storedName',
  authenticate,
  sensitiveRateLimiter,
  [validateMongoId('recordId')],
  handleValidationErrors,
  async (req, res) => {
    try {
      const record = await MedicalRecord.findOne({ _id: { $eq: req.params.recordId } });
      if (!record) return res.status(404).json({ error: 'Record not found' });

      // IDOR: verify the document belongs to this record
      const docEntry = record.documents.find((d) => d.storedName === req.params.storedName);
      if (!docEntry) return res.status(404).json({ error: 'Document not found in this record' });

      // RBAC: patient must own the record, or doctor authored it, or admin/nurse
      const isOwner =
        String(record.patient) === req.user.id ||
        String(record.doctor)  === req.user.id;
      const isPrivileged = ['admin', 'nurse'].includes(req.user.role);
      if (!isOwner && !isPrivileged) return res.status(403).json({ error: 'Access denied' });

      // Log before decrypting — always record intent
      await log({
        action: ACTIONS.DOCUMENT_VIEW,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.storedName,
        targetType: 'Document',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      // Decrypt and stream the file
      const fileBuffer = retrieveDocument(req.params.storedName);
      res.setHeader('Content-Type', docEntry.mimeType);
      res.setHeader('Content-Disposition', `attachment; filename="${docEntry.originalName}"`);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      return res.send(fileBuffer);
    } catch (err) {
      const status = err.status || 500;
      return res.status(status).json({ error: err.message || 'Failed to retrieve document' });
    }
  }
);

// ─── DELETE /documents/:recordId/:storedName ──────────────────────────────────
router.delete(
  '/:recordId/:storedName',
  authenticate,
  requireRole('admin', 'doctor'),
  [validateMongoId('recordId')],
  handleValidationErrors,
  async (req, res) => {
    try {
      const record = await MedicalRecord.findOne({ _id: { $eq: req.params.recordId } });
      if (!record) return res.status(404).json({ error: 'Record not found' });

      const docIdx = record.documents.findIndex((d) => d.storedName === req.params.storedName);
      if (docIdx === -1) return res.status(404).json({ error: 'Document not found' });

      // Doctor can only delete their own record's documents
      if (req.user.role === 'doctor' && String(record.doctor) !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
      }

      deleteDocument(req.params.storedName);
      record.documents.splice(docIdx, 1);
      await record.save();

      await log({
        action: ACTIONS.DOCUMENT_DELETE,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.storedName,
        targetType: 'Document',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ message: 'Document deleted' });
    } catch (err) {
      return res.status(500).json({ error: 'Failed to delete document' });
    }
  }
);

module.exports = router;
