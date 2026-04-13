'use strict';

const express = require('express');
const { body, param } = require('express-validator');
const Account = require('../models/Account');
const auditService = require('../services/auditService');
const { requireAuth, requireRole } = require('../middleware/auth');
const { handleValidation } = require('../middleware/validate');

const router = express.Router();

// ─── GET /accounts ────────────────────────────────────────────────────────────
/**
 * List all accounts belonging to the authenticated user.
 * Account numbers are excluded from the response (select: false in schema).
 */
router.get('/', requireAuth, async (req, res, next) => {
  try {
    // Scope query to authenticated user — prevents cross-user data access (Task 3)
    const accounts = await Account.find({ owner: req.user.sub, isActive: true })
      .select('-accountNumber -routingNumber') // never return sensitive fields
      .lean();
    res.json({ data: accounts });
  } catch (err) {
    next(err);
  }
});

// ─── GET /accounts/:accountId ─────────────────────────────────────────────────
/**
 * Get a single account by ID.
 * Ownership enforced in query — no need for separate middleware when filtering by owner.
 */
router.get(
  '/:accountId',
  requireAuth,
  [param('accountId').isMongoId()],
  handleValidation,
  async (req, res, next) => {
    try {
      const account = await Account.findOne({
        _id: req.params.accountId,
        owner: req.user.sub, // prevents parameter tampering (Task 3)
        isActive: true,
      })
        .select('-accountNumber -routingNumber')
        .lean();

      if (!account) return res.status(404).json({ error: 'Account not found' });
      res.json({ data: account });
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /accounts ───────────────────────────────────────────────────────────
/**
 * Open a new account for the authenticated user.
 */
router.post(
  '/',
  requireAuth,
  [
    body('type').isIn(['checking', 'savings']).withMessage('type must be checking or savings'),
  ],
  handleValidation,
  async (req, res, next) => {
    try {
      // Generate account and routing numbers server-side — never trust client input
      const crypto = require('crypto');
      const accountNumber = crypto.randomInt(10_000_000, 99_999_999).toString();
      const routingNumber = '021000021'; // Example routing number

      const account = await Account.create({
        owner: req.user.sub,
        type: req.body.type,
        accountNumber,
        routingNumber,
      });

      await auditService.log({
        userId: req.user.sub,
        action: 'account_created',
        resourceType: 'Account',
        resourceId: account._id.toString(),
        ipAddress: req.ip,
        severity: 'medium',
      });

      res.status(201).json({ data: { _id: account._id, type: account.type, balanceCents: 0 } });
    } catch (err) {
      next(err);
    }
  },
);

// ─── GET /accounts/:accountId/balance ─────────────────────────────────────────
/**
 * Check balance of a specific account.
 * Ownership verified in query filter.
 */
router.get(
  '/:accountId/balance',
  requireAuth,
  [param('accountId').isMongoId()],
  handleValidation,
  async (req, res, next) => {
    try {
      const account = await Account.findOne({
        _id: req.params.accountId,
        owner: req.user.sub,
        isActive: true,
      })
        .select('balanceCents currency')
        .lean();

      if (!account) return res.status(404).json({ error: 'Account not found' });
      res.json({ data: { balanceCents: account.balanceCents, currency: account.currency } });
    } catch (err) {
      next(err);
    }
  },
);

// ─── DELETE /accounts/:accountId (admin only) ─────────────────────────────────
/**
 * Close an account — admin-only operation.
 */
router.delete(
  '/:accountId',
  requireAuth,
  requireRole('admin'),
  [param('accountId').isMongoId()],
  handleValidation,
  async (req, res, next) => {
    try {
      const account = await Account.findByIdAndUpdate(
        req.params.accountId,
        { isActive: false },
        { new: true },
      );
      if (!account) return res.status(404).json({ error: 'Account not found' });

      await auditService.log({
        userId: req.user.sub,
        action: 'account_closed',
        resourceType: 'Account',
        resourceId: req.params.accountId,
        severity: 'high',
      });

      res.json({ message: 'Account closed' });
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
