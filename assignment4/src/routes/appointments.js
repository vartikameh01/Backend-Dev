'use strict';

/**
 * appointments.js (routes)
 * Task 4: Secure appointment lookup.
 * Task 2: Date validation with ISO 8601 enforcement.
 */

const express = require('express');
const router = express.Router();

const Appointment = require('../models/Appointment');
const { authenticate } = require('../middleware/auth');
const { requireOwnerOrRole, requireRole } = require('../middleware/rbac');
const { handleValidationErrors } = require('../middleware/validate');
const { log, ACTIONS } = require('../services/auditService');
const { sanitizePlainText } = require('../utils/sanitizers');
const {
  validateMongoId,
  validateAppointmentDate,
  validateAppointmentReason,
} = require('../utils/validators');
const { query } = require('express-validator');

// ─── POST /appointments ───────────────────────────────────────────────────────
router.post(
  '/',
  authenticate,
  requireRole('patient', 'doctor', 'admin', 'nurse'),
  [
    validateMongoId('doctorId').replace([/* override param name */], 'body'),
    validateAppointmentDate(),
    validateAppointmentReason(),
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { doctorId, appointmentDate, reason, isVirtual } = req.body;

      // Patient can only book for themselves unless admin/staff
      const patientId = ['admin', 'doctor', 'nurse'].includes(req.user.role)
        ? (req.body.patientId || req.user.id)
        : req.user.id;

      const appointment = new Appointment({
        patient: patientId,
        doctor:  sanitizePlainText(doctorId),
        appointmentDate: new Date(appointmentDate),
        isVirtual: Boolean(isVirtual),
      });
      appointment.reason = sanitizePlainText(reason); // encrypted via virtual setter

      await appointment.save();

      await log({
        action: ACTIONS.APPOINTMENT_CREATE,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: String(appointment._id),
        targetType: 'Appointment',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(201).json({ message: 'Appointment scheduled', id: appointment._id });
    } catch {
      return res.status(500).json({ error: 'Failed to schedule appointment' });
    }
  }
);

// ─── GET /appointments/:id ────────────────────────────────────────────────────
// Task 4: Lookup by exact _id ($eq) — no operator injection possible
router.get(
  '/:id',
  authenticate,
  [validateMongoId('id')],
  handleValidationErrors,
  async (req, res) => {
    try {
      // Use explicit { _id: { $eq: ... } } to make injection impossible
      const appointment = await Appointment.findOne({ _id: { $eq: req.params.id } })
        .populate('patient', 'email _enc_firstName _enc_lastName')
        .populate('doctor',  'email npi specialties');

      if (!appointment) return res.status(404).json({ error: 'Appointment not found' });

      // IDOR: only the patient, their doctor, or admin/nurse may view
      const isOwner =
        String(appointment.patient._id) === req.user.id ||
        String(appointment.doctor._id)  === req.user.id;
      const isPrivileged = ['admin', 'nurse'].includes(req.user.role);

      if (!isOwner && !isPrivileged) {
        return res.status(403).json({ error: 'Access denied' });
      }

      await log({
        action: ACTIONS.APPOINTMENT_VIEW,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.id,
        targetType: 'Appointment',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json(appointment);
    } catch {
      return res.status(500).json({ error: 'Failed to retrieve appointment' });
    }
  }
);

// ─── GET /appointments — list with date filter ────────────────────────────────
router.get(
  '/',
  authenticate,
  [
    query('from').optional().isISO8601().withMessage('from must be ISO 8601').toDate(),
    query('to').optional().isISO8601().withMessage('to must be ISO 8601').toDate(),
    query('status').optional().isIn(['scheduled', 'confirmed', 'cancelled', 'completed', 'no_show']),
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 50 }),
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { from, to, status, page = 1, limit = 20 } = req.query;
      const pageNum  = Math.max(1, parseInt(page, 10));
      const limitNum = Math.min(50, Math.max(1, parseInt(limit, 10)));

      // Scope by role — patients only see their own, doctors see theirs
      const filter = {};
      if (req.user.role === 'patient') filter.patient = req.user.id;
      else if (req.user.role === 'doctor') filter.doctor = req.user.id;
      // admin/nurse can see all

      if (from || to) {
        filter.appointmentDate = {};
        if (from) filter.appointmentDate.$gte = new Date(from);
        if (to)   filter.appointmentDate.$lte = new Date(to);
      }
      if (status) filter.status = { $eq: status };

      const [appointments, total] = await Promise.all([
        Appointment.find(filter).skip((pageNum - 1) * limitNum).limit(limitNum).lean(),
        Appointment.countDocuments(filter),
      ]);

      return res.json({ appointments, total, page: pageNum, pages: Math.ceil(total / limitNum) });
    } catch {
      return res.status(500).json({ error: 'Failed to list appointments' });
    }
  }
);

// ─── PATCH /appointments/:id/cancel ───────────────────────────────────────────
router.patch(
  '/:id/cancel',
  authenticate,
  [validateMongoId('id')],
  handleValidationErrors,
  async (req, res) => {
    try {
      const appointment = await Appointment.findOne({ _id: { $eq: req.params.id } });
      if (!appointment) return res.status(404).json({ error: 'Appointment not found' });

      const isOwner = [String(appointment.patient), String(appointment.doctor)].includes(req.user.id);
      if (!isOwner && !['admin', 'nurse'].includes(req.user.role)) {
        return res.status(403).json({ error: 'Access denied' });
      }

      appointment.status = 'cancelled';
      appointment.cancelledBy = req.user.id;
      if (req.body.note) {
        appointment.cancellationNote = sanitizePlainText(String(req.body.note)).slice(0, 500);
      }
      await appointment.save();

      await log({
        action: ACTIONS.APPOINTMENT_CANCEL,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: req.params.id,
        targetType: 'Appointment',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ message: 'Appointment cancelled' });
    } catch {
      return res.status(500).json({ error: 'Failed to cancel appointment' });
    }
  }
);

module.exports = router;
