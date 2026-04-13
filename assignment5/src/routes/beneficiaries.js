'use strict';

const express = require('express');
const { param } = require('express-validator');
const Beneficiary = require('../models/Beneficiary');
const auditService = require('../services/auditService');
const { requireAuth } = require('../middleware/auth');
const { handleValidation } = require('../middleware/validate');
const { beneficiaryRules } = require('../utils/validators');
const { sanitizeText } = require('../utils/sanitizers');

const router = express.Router();

// ─── GET /beneficiaries ───────────────────────────────────────────────────────
/**
 * List all beneficiaries for the authenticated user.
 * Account/routing numbers excluded (select: false).
 */
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const beneficiaries = await Beneficiary.find({ owner: req.user.sub, isActive: true })
      .select('-accountNumber -routingNumber')
      .lean();
    res.json({ data: beneficiaries });
  } catch (err) {
    next(err);
  }
});

// ─── POST /beneficiaries ──────────────────────────────────────────────────────
/**
 * Add a new beneficiary.
 * Nickname and bankName sanitized before storage (Task 2 — input sanitization).
 */
router.post(
  '/',
  requireAuth,
  beneficiaryRules(),
  handleValidation,
  async (req, res, next) => {
    try {
      const { nickname, accountNumber, routingNumber, bankName } = req.body;

      const beneficiary = await Beneficiary.create({
        owner: req.user.sub,
        nickname: sanitizeText(nickname),
        accountNumber, // encrypted by schema plugin
        routingNumber,
        bankName: sanitizeText(bankName),
      });

      await auditService.log({
        userId: req.user.sub,
        action: 'beneficiary_added',
        resourceType: 'Beneficiary',
        resourceId: beneficiary._id.toString(),
        ipAddress: req.ip,
        severity: 'medium',
      });

      res.status(201).json({
        data: { _id: beneficiary._id, nickname: beneficiary.nickname, bankName: beneficiary.bankName },
      });
    } catch (err) {
      next(err);
    }
  },
);

// ─── DELETE /beneficiaries/:id ────────────────────────────────────────────────
/**
 * Remove a beneficiary (soft delete).
 * Owner check in query filter prevents deleting another user's beneficiaries.
 */
router.delete(
  '/:id',
  requireAuth,
  [param('id').isMongoId()],
  handleValidation,
  async (req, res, next) => {
    try {
      const result = await Beneficiary.findOneAndUpdate(
        { _id: req.params.id, owner: req.user.sub }, // ownership enforced
        { isActive: false },
      );

      if (!result) return res.status(404).json({ error: 'Beneficiary not found' });

      await auditService.log({
        userId: req.user.sub,
        action: 'beneficiary_removed',
        resourceType: 'Beneficiary',
        resourceId: req.params.id,
        severity: 'medium',
      });

      res.json({ message: 'Beneficiary removed' });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
