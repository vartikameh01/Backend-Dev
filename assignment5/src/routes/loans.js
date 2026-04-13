'use strict';

const express = require('express');
const { body, param } = require('express-validator');
const Loan = require('../models/Loan');
const auditService = require('../services/auditService');
const { requireAuth, requireRole } = require('../middleware/auth');
const { handleValidation } = require('../middleware/validate');
const { sanitizeText } = require('../utils/sanitizers');

const router = express.Router();

// ─── POST /loans ──────────────────────────────────────────────────────────────
/**
 * Submit a loan application.
 */
router.post(
  '/',
  requireAuth,
  [
    body('principalCents').isInt({ min: 10000, max: 100_000_000 }).toInt(),
    body('termMonths').isInt({ min: 1, max: 360 }).toInt(),
    body('purpose').optional().isLength({ max: 200 }).trim(),
  ],
  handleValidation,
  async (req, res, next) => {
    try {
      const { principalCents, termMonths, purpose } = req.body;

      const loan = await Loan.create({
        applicant: req.user.sub,
        principalCents,
        termMonths,
        interestRateBps: 500, // 5.00% placeholder — set by underwriting in production
        purpose: sanitizeText(purpose || ''),
      });

      await auditService.log({
        userId: req.user.sub,
        action: 'loan_requested',
        resourceType: 'Loan',
        resourceId: loan._id.toString(),
        metadata: { principalCents, termMonths },
        severity: 'medium',
      });

      res.status(201).json({ data: loan });
    } catch (err) {
      next(err);
    }
  },
);

// ─── GET /loans ───────────────────────────────────────────────────────────────
/**
 * List the authenticated user's loan applications.
 */
router.get('/', requireAuth, async (req, res, next) => {
  try {
    // Always filter by applicant — prevents horizontal data exposure
    const loans = await Loan.find({ applicant: req.user.sub }).lean();
    res.json({ data: loans });
  } catch (err) {
    next(err);
  }
});

// ─── PATCH /loans/:id/review (admin only) ─────────────────────────────────────
/**
 * Admin reviews a loan application.
 */
router.patch(
  '/:id/review',
  requireAuth,
  requireRole('admin'),
  [
    param('id').isMongoId(),
    body('status').isIn(['approved', 'rejected', 'under_review']),
    body('reviewNotes').optional().isLength({ max: 1000 }).trim(),
  ],
  handleValidation,
  async (req, res, next) => {
    try {
      const loan = await Loan.findByIdAndUpdate(
        req.params.id,
        {
          status: req.body.status,
          reviewNotes: sanitizeText(req.body.reviewNotes || ''),
          reviewedBy: req.user.sub,
          reviewedAt: new Date(),
        },
        { new: true },
      );

      if (!loan) return res.status(404).json({ error: 'Loan not found' });

      const action = req.body.status === 'approved' ? 'loan_approved' : 'loan_rejected';
      await auditService.log({
        userId: req.user.sub,
        action,
        resourceType: 'Loan',
        resourceId: req.params.id,
        severity: 'high',
      });

      res.json({ data: loan });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
