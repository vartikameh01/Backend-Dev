'use strict';

const express = require('express');
const { body } = require('express-validator');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const { handleValidation } = require('../middleware/validate');
const { auditProfileUpdate } = require('../middleware/auditLogger');
const { sanitizeText } = require('../utils/sanitizers');
const { passwordRules } = require('../utils/validators');

const router = express.Router();

// ─── GET /profile ─────────────────────────────────────────────────────────────
/**
 * Get current user's profile. Sensitive fields stripped by toSafeObject().
 */
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ data: user.toSafeObject() });
  } catch (err) {
    next(err);
  }
});

// ─── PATCH /profile ───────────────────────────────────────────────────────────
/**
 * Update profile information.
 * - Input sanitized (sanitizeText) before storage (Task 3)
 * - Only whitelisted fields are accepted — no mass assignment
 * - Audit logged (auditProfileUpdate middleware)
 */
router.patch(
  '/',
  requireAuth,
  [
    body('firstName').optional().isLength({ min: 1, max: 50 }).trim(),
    body('lastName').optional().isLength({ min: 1, max: 50 }).trim(),
    body('phone')
      .optional()
      .matches(/^\+?[\d\s\-().]{7,20}$/)
      .withMessage('Invalid phone number format'),
    body('emailNotifications').optional().isBoolean(),
  ],
  handleValidation,
  auditProfileUpdate,
  async (req, res, next) => {
    try {
      // Whitelist — only allow these fields (prevents parameter tampering / mass assignment)
      const allowedFields = ['firstName', 'lastName', 'phone', 'emailNotifications'];
      const updates = {};
      for (const field of allowedFields) {
        if (req.body[field] !== undefined) {
          // Sanitize string fields
          updates[field] = typeof req.body[field] === 'string'
            ? sanitizeText(req.body[field])
            : req.body[field];
        }
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: 'No valid fields to update' });
      }

      const user = await User.findByIdAndUpdate(req.user.sub, updates, { new: true, runValidators: true });
      if (!user) return res.status(404).json({ error: 'User not found' });

      res.json({ data: user.toSafeObject() });
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /profile/change-password ────────────────────────────────────────────
/**
 * Change password — requires current password confirmation.
 */
router.post(
  '/change-password',
  requireAuth,
  [
    body('currentPassword').notEmpty(),
    passwordRules('newPassword'),
  ],
  handleValidation,
  async (req, res, next) => {
    try {
      const user = await User.findById(req.user.sub).select('+passwordHash');
      if (!user) return res.status(404).json({ error: 'User not found' });

      const valid = await user.verifyPassword(req.body.currentPassword);
      if (!valid) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      await user.setPassword(req.body.newPassword);
      await user.save();

      res.json({ message: 'Password updated successfully' });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
