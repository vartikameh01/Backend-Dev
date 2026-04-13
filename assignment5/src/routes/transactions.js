'use strict';

const express = require('express');
const { body } = require('express-validator');
const transactionService = require('../services/transactionService');
const authService = require('../services/authService');
const { requireAuth, require2FAVerified } = require('../middleware/auth');
const { handleValidation } = require('../middleware/validate');
const { transferLimiter, billPaymentLimiter, twoFactorLimiter } = require('../middleware/rateLimiter');
const { auditTransaction } = require('../middleware/auditLogger');
const { amountRules, accountIdRules, transactionSearchRules } = require('../utils/validators');
const security = require('../config/security');

const router = express.Router();

// ─── 2FA check middleware ──────────────────────────────────────────────────────
/**
 * check2FAForHighValue
 * For transactions above the 2FA threshold, requires the client to send
 * x-2fa-token header containing a valid TOTP code.
 * Sets req.twoFactorVerified = true if passed.
 */
async function check2FAForHighValue(req, res, next) {
  const amountCents = parseInt(req.body.amountCents, 10);

  if (isNaN(amountCents) || amountCents < security.tx2faThresholdCents) {
    req.twoFactorVerified = false;
    return next();
  }

  const otp = req.headers['x-2fa-token'];
  if (!otp) {
    return res.status(403).json({
      error: '2FA verification required for transactions above $' + (security.tx2faThresholdCents / 100),
      code: '2FA_REQUIRED',
    });
  }

  const valid = await authService.verify2FA(req.user.sub, otp, {
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
  });

  if (!valid) {
    return res.status(403).json({ error: 'Invalid 2FA token', code: '2FA_INVALID' });
  }

  req.twoFactorVerified = true;
  next();
}

// ─── POST /transactions/transfer ──────────────────────────────────────────────
/**
 * Initiate a money transfer.
 * Security controls:
 * - requireAuth: valid JWT
 * - transferLimiter: 10 req/min per IP
 * - amountRules: server-side amount/limit validation (fixes $1M transfer exploit)
 * - check2FAForHighValue: TOTP required for amounts >= $1,000
 * - require2FAVerified: gate enforces 2FA was actually checked
 * - auditTransaction: writes financial audit log entry
 */
router.post(
  '/transfer',
  requireAuth,
  transferLimiter,
  [
    amountRules('amountCents', security.singleTxLimitCents),
    accountIdRules('fromAccountId'),
    body('toAccountId').isMongoId().withMessage('Invalid destination account'),
    body('description').optional().isLength({ max: 500 }).trim(),
  ],
  handleValidation,
  check2FAForHighValue,
  require2FAVerified,
  auditTransaction('transfer_initiated'),
  async (req, res, next) => {
    try {
      const { fromAccountId, toAccountId, amountCents, description } = req.body;
      const tx = await transactionService.transfer(
        fromAccountId,
        toAccountId,
        amountCents,
        description,
        req.user.sub,
        {
          ipAddress: req.ip,
          deviceFingerprint: req.deviceFingerprint,
          twoFactorVerified: req.twoFactorVerified,
        },
      );
      res.status(201).json({ message: 'Transfer completed', data: tx });
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /transactions/bill-payment ─────────────────────────────────────────
/**
 * Pay a bill from an account.
 */
router.post(
  '/bill-payment',
  requireAuth,
  billPaymentLimiter,
  [
    amountRules('amountCents', security.singleTxLimitCents),
    accountIdRules('fromAccountId'),
    body('referenceNumber').isLength({ min: 1, max: 50 }).matches(/^[\w\-]+$/),
    body('description').optional().isLength({ max: 500 }).trim(),
  ],
  handleValidation,
  check2FAForHighValue,
  require2FAVerified,
  auditTransaction('bill_payment_initiated'),
  async (req, res, next) => {
    try {
      const { fromAccountId, amountCents, referenceNumber, description } = req.body;
      const tx = await transactionService.payBill(
        fromAccountId,
        amountCents,
        referenceNumber,
        description,
        req.user.sub,
        {
          ipAddress: req.ip,
          deviceFingerprint: req.deviceFingerprint,
          twoFactorVerified: req.twoFactorVerified,
        },
      );
      res.status(201).json({ message: 'Bill payment processed', data: tx });
    } catch (err) {
      next(err);
    }
  },
);

// ─── GET /transactions ────────────────────────────────────────────────────────
/**
 * Get paginated transaction history for the authenticated user.
 * Query is ALWAYS scoped to accounts owned by req.user.sub — prevents cross-user data access.
 * Fixes the "transaction history searches can view other users' transactions" vulnerability.
 */
router.get(
  '/',
  requireAuth,
  transactionSearchRules(),
  handleValidation,
  async (req, res, next) => {
    try {
      const result = await transactionService.getTransactionHistory(req.user.sub, {
        startDate: req.query.startDate,
        endDate: req.query.endDate,
        type: req.query.type,
        page: req.query.page,
        limit: req.query.limit,
      });
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
