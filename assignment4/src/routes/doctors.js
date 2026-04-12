'use strict';

/**
 * doctors.js (routes)
 * Task 4: Secure doctor availability queries — no operator injection.
 * Availability search uses explicit date range with $gte/$lte on validated ISO dates.
 */

const express = require('express');
const router = express.Router();

const { User } = require('../models/User');
const Appointment = require('../models/Appointment');
const { authenticate } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { handleValidationErrors } = require('../middleware/validate');
const { sanitizePlainText } = require('../utils/sanitizers');
const { validateMongoId, validateNPI, validateSearchQuery, validateName } = require('../utils/validators');
const { query, param } = require('express-validator');

// ─── GET /doctors — search for doctors ───────────────────────────────────────
// Task 4: Never pass user input directly into the query filter.
// Specialty search uses $eq (exact match), not regex — prevents ReDoS + injection.
router.get(
  '/',
  authenticate,
  [
    validateSearchQuery(),
    query('specialty').optional().trim().isLength({ max: 100 }),
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 50 }),
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { specialty, page = 1, limit = 20 } = req.query;
      const pageNum  = Math.max(1, parseInt(page, 10));
      const limitNum = Math.min(50, Math.max(1, parseInt(limit, 10)));

      const filter = { role: 'doctor', isActive: true };

      if (specialty) {
        // Exact equality inside array — prevents injection via regex operators
        const safeSpecialty = sanitizePlainText(specialty);
        filter.specialties = { $eq: safeSpecialty };
      }

      const [doctors, total] = await Promise.all([
        User.find(filter, 'email npi specialties licenseNumber')
            .skip((pageNum - 1) * limitNum)
            .limit(limitNum)
            .lean(),
        User.countDocuments(filter),
      ]);

      return res.json({ doctors, total, page: pageNum, pages: Math.ceil(total / limitNum) });
    } catch {
      return res.status(500).json({ error: 'Doctor search failed' });
    }
  }
);

// ─── GET /doctors/:id/availability ────────────────────────────────────────────
// Task 4: Date-range query with explicit typed parameters.
// No raw string passed to query; dates are validated ISO 8601 and cast to Date objects.
router.get(
  '/:id/availability',
  authenticate,
  [
    validateMongoId('id'),
    query('date')
      .notEmpty().withMessage('date is required')
      .isISO8601().withMessage('date must be a valid ISO 8601 date')
      .toDate(),
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const doctorId = req.params.id;
      const date     = new Date(req.query.date);

      // Build explicit date range for the queried day
      const startOfDay = new Date(date);
      startOfDay.setUTCHours(0, 0, 0, 0);
      const endOfDay = new Date(date);
      endOfDay.setUTCHours(23, 59, 59, 999);

      const doctor = await User.findOne({ _id: doctorId, role: 'doctor' });
      if (!doctor) return res.status(404).json({ error: 'Doctor not found' });

      // Find existing appointments for this doctor on the requested day
      // Using explicit typed $gte/$lte — NOT string comparison
      const bookedSlots = await Appointment.find({
        doctor: doctorId,
        appointmentDate: { $gte: startOfDay, $lte: endOfDay },
        status: { $in: ['scheduled', 'confirmed'] },
      }).select('appointmentDate durationMinutes -_id');

      return res.json({ doctorId, date: date.toISOString().split('T')[0], bookedSlots });
    } catch {
      return res.status(500).json({ error: 'Failed to fetch availability' });
    }
  }
);

// ─── POST /doctors — create doctor profile (admin only) ──────────────────────
router.post(
  '/',
  authenticate,
  requireRole('admin'),
  [
    validateName('firstName'),
    validateName('lastName'),
    query('email').notEmpty(),
    validateNPI(),
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { firstName, lastName, email, npi, specialties, licenseNumber, password } = req.body;

      const existing = await User.findOne({ email });
      if (existing) return res.status(409).json({ error: 'Email already registered' });

      const doctor = new User({ email, password, role: 'doctor', npi, specialties, licenseNumber });
      doctor.firstName = firstName;
      doctor.lastName  = lastName;
      await doctor.save();

      return res.status(201).json({ message: 'Doctor created', id: doctor._id });
    } catch {
      return res.status(500).json({ error: 'Failed to create doctor' });
    }
  }
);

module.exports = router;
