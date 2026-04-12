'use strict';

/**
 * medicalRecords.js (routes)
 * Task 1 (IDOR fix): Record access strictly tied to patient ownership or role.
 * Task 2: All free-text fields sanitized via sanitizeMedicalText (XSS prevention).
 * Task 4: All queries use explicit typed filters — no operator injection.
 * Task 7: Every view/create/update/delete is audit-logged.
 */

const express = require('express');
const router = express.Router();

const MedicalRecord = require('../models/MedicalRecord');
const { authenticate } = require('../middleware/auth');
const { requireOwnerOrRole, requireRole } = require('../middleware/rbac');
const { sensitiveRateLimiter } = require('../middleware/rateLimiter');
const { handleValidationErrors } = require('../middleware/validate');
const { log, ACTIONS } = require('../services/auditService');
const { sanitizeMedicalText, sanitizeDoctorNotes } = require('../utils/sanitizers');
const { validateMongoId, validateMedicalText } = require('../utils/validators');
const { body, query } = require('express-validator');

// ─── GET /medical-records/:patientId — list a patient's records ───────────────
router.get(
  '/patient/:patientId',
  authenticate,
  sensitiveRateLimiter,
  requireOwnerOrRole('doctor', 'nurse', 'admin'),
  [validateMongoId('patientId')],
  handleValidationErrors,
  async (req, res) => {
    try {
      const records = await MedicalRecord.find({
        patient: { $eq: req.params.patientId },  // explicit $eq prevents operator injection
      })
        .populate('doctor', 'email npi specialties')
        .lean();

      await log({
        action: ACTIONS.RECORD_VIEW,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.patientId,
        targetType: 'Patient',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: { recordCount: records.length },
      });

      return res.json(records);
    } catch {
      return res.status(500).json({ error: 'Failed to retrieve medical records' });
    }
  }
);

// ─── GET /medical-records/:id — retrieve single record ───────────────────────
router.get(
  '/:id',
  authenticate,
  sensitiveRateLimiter,
  [validateMongoId('id')],
  handleValidationErrors,
  async (req, res) => {
    try {
      const record = await MedicalRecord.findOne({ _id: { $eq: req.params.id } })
        .populate('patient', 'email')
        .populate('doctor', 'email npi');

      if (!record) return res.status(404).json({ error: 'Record not found' });

      // IDOR: patient owns this record, or doctor wrote it, or admin/nurse
      const isOwner =
        String(record.patient._id) === req.user.id ||
        String(record.doctor._id)  === req.user.id;
      const isPrivileged = ['admin', 'nurse'].includes(req.user.role);
      if (!isOwner && !isPrivileged) return res.status(403).json({ error: 'Access denied' });

      await log({
        action: ACTIONS.RECORD_VIEW,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.id,
        targetType: 'MedicalRecord',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json(record);
    } catch {
      return res.status(500).json({ error: 'Failed to retrieve record' });
    }
  }
);

// ─── POST /medical-records — create ───────────────────────────────────────────
router.post(
  '/',
  authenticate,
  requireRole('doctor', 'admin'),
  sensitiveRateLimiter,
  [
    body('patientId').isMongoId().withMessage('patientId must be a valid ID'),
    body('visitDate').isISO8601().withMessage('visitDate must be ISO 8601').toDate(),
    validateMedicalText('diagnosis', 2000),
    validateMedicalText('symptoms',  2000),
    validateMedicalText('notes',     5000),
    validateMedicalText('treatmentPlan', 5000),
    validateMedicalText('allergies', 1000),
    validateMedicalText('medications', 2000),
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { patientId, visitDate, diagnosis, symptoms, notes, treatmentPlan, allergies, medications, appointmentId } = req.body;

      const record = new MedicalRecord({
        patient:     patientId,
        doctor:      req.user.id,
        visitDate:   new Date(visitDate),
        appointment: appointmentId || undefined,
      });

      // Sanitize all free-text medical fields before storing (Task 2: XSS prevention)
      if (diagnosis)     record.diagnosis     = sanitizeMedicalText(diagnosis);
      if (symptoms)      record.symptoms      = sanitizeMedicalText(symptoms);
      if (notes)         record.notes         = sanitizeDoctorNotes(notes);
      if (treatmentPlan) record.treatmentPlan = sanitizeMedicalText(treatmentPlan);
      if (allergies)     record.allergies     = sanitizeMedicalText(allergies);
      if (medications)   record.medications   = sanitizeMedicalText(medications);

      await record.save();

      await log({
        action: ACTIONS.RECORD_CREATE,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: String(record._id),
        targetType: 'MedicalRecord',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(201).json({ message: 'Medical record created', id: record._id });
    } catch {
      return res.status(500).json({ error: 'Failed to create medical record' });
    }
  }
);

// ─── PUT /medical-records/:id — update ────────────────────────────────────────
router.put(
  '/:id',
  authenticate,
  requireRole('doctor', 'admin'),
  sensitiveRateLimiter,
  [
    validateMongoId('id'),
    validateMedicalText('diagnosis', 2000),
    validateMedicalText('symptoms',  2000),
    validateMedicalText('notes',     5000),
    validateMedicalText('treatmentPlan', 5000),
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const record = await MedicalRecord.findOne({ _id: { $eq: req.params.id } });
      if (!record) return res.status(404).json({ error: 'Record not found' });

      // Only the authoring doctor or admin can update
      if (req.user.role !== 'admin' && String(record.doctor) !== req.user.id) {
        return res.status(403).json({ error: 'Only the authoring doctor may update this record' });
      }

      const fields = ['diagnosis', 'symptoms', 'notes', 'treatmentPlan', 'allergies', 'medications'];
      fields.forEach((f) => {
        if (req.body[f] !== undefined) record[f] = sanitizeMedicalText(req.body[f]);
      });
      await record.save();

      await log({
        action: ACTIONS.RECORD_UPDATE,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.id,
        targetType: 'MedicalRecord',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ message: 'Medical record updated' });
    } catch {
      return res.status(500).json({ error: 'Failed to update record' });
    }
  }
);

// ─── DELETE /medical-records/:id (soft delete) ────────────────────────────────
router.delete(
  '/:id',
  authenticate,
  requireRole('admin'),
  [validateMongoId('id')],
  handleValidationErrors,
  async (req, res) => {
    try {
      const record = await MedicalRecord.findOneAndUpdate(
        { _id: { $eq: req.params.id } },
        { $set: { isDeleted: true } },
        { new: true }
      );
      if (!record) return res.status(404).json({ error: 'Record not found' });

      await log({
        action: ACTIONS.RECORD_DELETE,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.id,
        targetType: 'MedicalRecord',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ message: 'Medical record deleted (soft)' });
    } catch {
      return res.status(500).json({ error: 'Failed to delete record' });
    }
  }
);

module.exports = router;
