'use strict';

/**
 * patients.js (routes)
 * Task 1 (IDOR fix): All patient data access requires ownership or elevated role.
 * Task 4: All MongoDB queries use parameterised field-level filters — no $where, no operator injection.
 */

const express = require('express');
const router = express.Router();

const { User } = require('../models/User');
const { authenticate } = require('../middleware/auth');
const { requireOwnerOrRole, requireRole } = require('../middleware/rbac');
const { sensitiveRateLimiter } = require('../middleware/rateLimiter');
const { handleValidationErrors } = require('../middleware/validate');
const { log, ACTIONS } = require('../services/auditService');
const { sanitizePlainText } = require('../utils/sanitizers');
const {
  validateMongoId,
  validateName,
  validatePhone,
  validateSSN,
  validateInsuranceId,
  validateSearchQuery,
} = require('../utils/validators');

// ─── GET /patients/:id  (IDOR-safe) ──────────────────────────────────────────
router.get(
  '/:id',
  authenticate,
  requireOwnerOrRole('doctor', 'nurse', 'admin'),
  [validateMongoId('id')],
  handleValidationErrors,
  async (req, res) => {
    try {
      const patient = await User.findOne({ _id: req.params.id, role: 'patient' });
      if (!patient) return res.status(404).json({ error: 'Patient not found' });

      await log({
        action: ACTIONS.PATIENT_VIEW,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.id,
        targetType: 'Patient',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json(patient);
    } catch {
      return res.status(500).json({ error: 'Failed to retrieve patient' });
    }
  }
);

// ─── PUT /patients/:id  (update own profile) ──────────────────────────────────
router.put(
  '/:id',
  authenticate,
  requireOwnerOrRole('admin'),
  [
    validateMongoId('id'),
    validateName('firstName').optional(),
    validateName('lastName').optional(),
    validatePhone(),
    validateSSN(),
    validateInsuranceId(),
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const patient = await User.findOne({ _id: req.params.id, role: 'patient' });
      if (!patient) return res.status(404).json({ error: 'Patient not found' });

      // Only update allowed fields (whitelist — no mass-assignment)
      const allowed = ['firstName', 'lastName', 'phone', 'address', 'ssn',
                       'insuranceMemberId', 'insuranceProvider', 'insurancePolicyNum'];
      allowed.forEach((field) => {
        if (req.body[field] !== undefined) {
          patient[field] = sanitizePlainText(req.body[field]);
        }
      });

      await patient.save();

      await log({
        action: ACTIONS.PATIENT_UPDATE,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.id,
        targetType: 'Patient',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: { updatedFields: allowed.filter((f) => req.body[f] !== undefined) },
      });

      return res.json(patient);
    } catch {
      return res.status(500).json({ error: 'Failed to update patient' });
    }
  }
);

// ─── GET /patients (admin search) ─────────────────────────────────────────────
// Task 4: Secure patient search — never use $where or raw regex on user input
router.get(
  '/',
  authenticate,
  requireRole('doctor', 'nurse', 'admin'),
  sensitiveRateLimiter,
  [validateSearchQuery()],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { q, page = 1, limit = 20 } = req.query;
      const pageNum  = Math.max(1, parseInt(page, 10));
      const limitNum = Math.min(50, Math.max(1, parseInt(limit, 10)));

      // Build filter — only exact email match or empty (list all for admin)
      // NEVER build a dynamic regex from user input (injection risk)
      const filter = { role: 'patient', isActive: true };
      if (q) {
        // Sanitised string — allow equality search on email only
        const safeQ = sanitizePlainText(q).toLowerCase();
        // Use $eq explicitly to prevent operator injection
        filter.email = { $eq: safeQ };
      }

      const [patients, total] = await Promise.all([
        User.find(filter)
            .skip((pageNum - 1) * limitNum)
            .limit(limitNum)
            .lean(),
        User.countDocuments(filter),
      ]);

      return res.json({ patients, total, page: pageNum, pages: Math.ceil(total / limitNum) });
    } catch {
      return res.status(500).json({ error: 'Search failed' });
    }
  }
);

// ─── DELETE /patients/:id (admin soft-delete) ─────────────────────────────────
router.delete(
  '/:id',
  authenticate,
  requireRole('admin'),
  [validateMongoId('id')],
  handleValidationErrors,
  async (req, res) => {
    try {
      // Soft delete: deactivate only — preserve for audit trail
      const patient = await User.findOneAndUpdate(
        { _id: req.params.id, role: 'patient' },
        { $set: { isActive: false } },
        { new: true }
      );
      if (!patient) return res.status(404).json({ error: 'Patient not found' });

      await log({
        action: ACTIONS.PATIENT_DELETE,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.id,
        targetType: 'Patient',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ message: 'Patient deactivated' });
    } catch {
      return res.status(500).json({ error: 'Failed to deactivate patient' });
    }
  }
);

module.exports = router;
