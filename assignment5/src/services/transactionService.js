'use strict';

const mongoose = require('mongoose');
const Account = require('../models/Account');
const Transaction = require('../models/Transaction');
const auditService = require('./auditService');
const notificationService = require('./notificationService');
const fraudDetectionService = require('./fraudDetectionService');
const { sanitizeText, sanitizeForEmail } = require('../utils/sanitizers');
const security = require('../config/security');
const logger = require('../utils/logger');

/**
 * transfer
 * Executes a money transfer between two accounts.
 *
 * Security controls (Task 2):
 * - Server-side amount validation (not trusting client value)
 * - Per-transaction and daily limit enforcement
 * - Ownership verification (fromAccount must belong to req.user)
 * - MongoDB session / atomic operation to prevent race conditions
 * - Fraud detection hook before completing
 * - Sanitized description before storage and email notification
 *
 * @param {string} fromAccountId
 * @param {string} toAccountId
 * @param {number} amountCents     - validated integer
 * @param {string} description     - user-supplied, will be sanitized here
 * @param {string} initiatedByUserId
 * @param {object} context         - { ipAddress, deviceFingerprint }
 * @returns {Transaction}
 */
async function transfer(fromAccountId, toAccountId, amountCents, description, initiatedByUserId, context) {
  // ── Server-side limit enforcement ──
  if (amountCents < 1 || amountCents > security.singleTxLimitCents) {
    throw Object.assign(
      new Error(`Transfer amount exceeds single-transaction limit of $${security.singleTxLimitCents / 100}`),
      { statusCode: 422 },
    );
  }

  // ── Sanitize description before any use ──
  const cleanDescription = sanitizeText(description || '');

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Lock both accounts for the duration of the transaction
    const fromAccount = await Account.findOne({
      _id: fromAccountId,
      owner: initiatedByUserId, // ownership check — user can only debit their own account
      isActive: true,
    }).session(session);

    if (!fromAccount) {
      throw Object.assign(new Error('Source account not found or access denied'), { statusCode: 403 });
    }

    const toAccount = await Account.findOne({ _id: toAccountId, isActive: true }).session(session);
    if (!toAccount) {
      throw Object.assign(new Error('Destination account not found'), { statusCode: 404 });
    }

    if (fromAccountId === toAccountId) {
      throw Object.assign(new Error('Cannot transfer to the same account'), { statusCode: 422 });
    }

    // ── Daily limit check ──
    fromAccount.resetDailyLimitIfNeeded();
    if (fromAccount.dailyTransferredCents + amountCents > security.dailyTxLimitCents) {
      throw Object.assign(
        new Error(`Daily transfer limit of $${security.dailyTxLimitCents / 100} exceeded`),
        { statusCode: 422 },
      );
    }

    // ── Sufficient funds check ──
    if (!fromAccount.hasSufficientFunds(amountCents)) {
      throw Object.assign(new Error('Insufficient funds'), { statusCode: 422 });
    }

    // ── Fraud detection ──
    const fraudSignal = await fraudDetectionService.evaluateTransfer({
      userId: initiatedByUserId,
      amountCents,
      fromAccountId,
      toAccountId,
      ...context,
    });

    if (fraudSignal.blocked) {
      await auditService.log({
        userId: initiatedByUserId,
        action: 'transfer_failed',
        metadata: { reason: 'fraud_detection', signal: fraudSignal.reason, amountCents },
        severity: 'critical',
        ...context,
      });
      throw Object.assign(new Error('Transaction blocked by fraud detection'), { statusCode: 403 });
    }

    // ── Debit / Credit ──
    fromAccount.balanceCents -= amountCents;
    fromAccount.dailyTransferredCents += amountCents;
    toAccount.balanceCents += amountCents;

    await fromAccount.save({ session });
    await toAccount.save({ session });

    const tx = await Transaction.create(
      [
        {
          fromAccount: fromAccountId,
          toAccount: toAccountId,
          initiatedBy: initiatedByUserId,
          type: 'transfer',
          amountCents,
          balanceAfterCents: fromAccount.balanceCents,
          description: cleanDescription,
          status: 'completed',
          twoFactorVerified: context.twoFactorVerified || false,
          ipAddress: context.ipAddress,
          deviceFingerprint: context.deviceFingerprint,
        },
      ],
      { session },
    );

    await session.commitTransaction();

    const savedTx = tx[0];
    logger.info('Transfer completed', { txId: savedTx._id, amountCents, from: fromAccountId, to: toAccountId });

    // ── Post-commit side effects (non-fatal) ──
    auditService
      .log({
        userId: initiatedByUserId,
        action: 'transfer_completed',
        resourceType: 'Transaction',
        resourceId: savedTx._id.toString(),
        metadata: { amountCents, fromAccountId, toAccountId },
        severity: 'high',
        ...context,
      })
      .catch((e) => logger.error('Audit log error post-transfer', { error: e.message }));

    // Email uses sanitizeForEmail — prevents XSS in email clients
    notificationService
      .sendTransactionNotification(initiatedByUserId, {
        type: 'transfer',
        amountCents,
        description: sanitizeForEmail(cleanDescription),
        transactionId: savedTx._id.toString(),
      })
      .catch((e) => logger.error('Notification error post-transfer', { error: e.message }));

    return savedTx;
  } catch (err) {
    await session.abortTransaction();
    throw err;
  } finally {
    session.endSession();
  }
}

/**
 * payBill
 * Processes a bill payment from a user account to an external reference.
 * Shares most controls with transfer but uses a reference number instead of a toAccount.
 *
 * @param {string} fromAccountId
 * @param {number} amountCents
 * @param {string} referenceNumber - biller reference
 * @param {string} description
 * @param {string} initiatedByUserId
 * @param {object} context
 */
async function payBill(fromAccountId, amountCents, referenceNumber, description, initiatedByUserId, context) {
  if (amountCents < 1 || amountCents > security.singleTxLimitCents) {
    throw Object.assign(new Error('Amount exceeds single-transaction limit'), { statusCode: 422 });
  }

  const cleanDesc = sanitizeText(description || '');

  const fromAccount = await Account.findOne({
    _id: fromAccountId,
    owner: initiatedByUserId,
    isActive: true,
  });

  if (!fromAccount) {
    throw Object.assign(new Error('Account not found or access denied'), { statusCode: 403 });
  }

  fromAccount.resetDailyLimitIfNeeded();
  if (fromAccount.dailyTransferredCents + amountCents > security.dailyTxLimitCents) {
    throw Object.assign(new Error('Daily limit exceeded'), { statusCode: 422 });
  }

  if (!fromAccount.hasSufficientFunds(amountCents)) {
    throw Object.assign(new Error('Insufficient funds'), { statusCode: 422 });
  }

  fromAccount.balanceCents -= amountCents;
  fromAccount.dailyTransferredCents += amountCents;
  await fromAccount.save();

  const tx = await Transaction.create({
    fromAccount: fromAccountId,
    initiatedBy: initiatedByUserId,
    type: 'bill_payment',
    amountCents,
    balanceAfterCents: fromAccount.balanceCents,
    description: cleanDesc,
    referenceNumber,
    status: 'completed',
    twoFactorVerified: context.twoFactorVerified || false,
    ipAddress: context.ipAddress,
    deviceFingerprint: context.deviceFingerprint,
  });

  auditService
    .log({
      userId: initiatedByUserId,
      action: 'bill_payment_completed',
      resourceId: tx._id.toString(),
      metadata: { amountCents, referenceNumber },
      severity: 'high',
      ...context,
    })
    .catch((e) => logger.error('Audit log error post-bill-payment', { error: e.message }));

  return tx;
}

/**
 * getTransactionHistory
 * Returns paginated transaction history for accounts owned by the requesting user.
 * Fixes: searches must be scoped to the authenticated user — prevents viewing others' data.
 *
 * @param {string} userId - enforced owner filter
 * @param {object} filters - { startDate, endDate, type, page, limit }
 */
async function getTransactionHistory(userId, { startDate, endDate, type, page = 1, limit = 20 } = {}) {
  // Fetch accounts owned by this user first
  const ownedAccounts = await Account.find({ owner: userId, isActive: true }).select('_id').lean();
  const accountIds = ownedAccounts.map((a) => a._id);

  // Build a safe query — only look at accounts belonging to this user
  const filter = {
    $or: [
      { fromAccount: { $in: accountIds } },
      { toAccount: { $in: accountIds } },
    ],
    initiatedBy: userId,
  };

  if (startDate) filter.createdAt = { ...filter.createdAt, $gte: new Date(startDate) };
  if (endDate) filter.createdAt = { ...filter.createdAt, $lte: new Date(endDate) };
  if (type) filter.type = type;

  const skip = (page - 1) * limit;
  const [transactions, total] = await Promise.all([
    Transaction.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    Transaction.countDocuments(filter),
  ]);

  return { transactions, total, page, limit };
}

module.exports = { transfer, payBill, getTransactionHistory };
