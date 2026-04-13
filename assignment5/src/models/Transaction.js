'use strict';

const mongoose = require('mongoose');

/**
 * Transaction model
 * Immutable audit record of every financial event.
 * - description is sanitized before storage (fixes XSS-in-email vulnerability).
 * - status follows a strict state machine: pending → completed | failed | reversed.
 * - twoFactorVerified flags whether 2FA was confirmed for high-value transactions.
 */
const transactionSchema = new mongoose.Schema(
  {
    fromAccount: { type: mongoose.Schema.Types.ObjectId, ref: 'Account', index: true },
    toAccount:   { type: mongoose.Schema.Types.ObjectId, ref: 'Account', index: true },

    // Initiating user (for authorization checks in history queries)
    initiatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },

    type: {
      type: String,
      enum: ['transfer', 'bill_payment', 'deposit', 'withdrawal', 'loan_disbursement', 'loan_repayment'],
      required: true,
    },

    amountCents: { type: Number, required: true, min: 1 },
    currency: { type: String, default: 'USD' },
    balanceAfterCents: { type: Number }, // snapshot for audit trail

    // Pre-sanitized (sanitizeForEmail / sanitizeText applied in service layer)
    description: { type: String, maxlength: 500, default: '' },

    status: {
      type: String,
      enum: ['pending', 'completed', 'failed', 'reversed'],
      default: 'pending',
    },

    // 2FA confirmation for high-value transactions (Task 2)
    twoFactorVerified: { type: Boolean, default: false },

    // Reference number for bill payments
    referenceNumber: { type: String },

    // IP and device at time of transaction (fraud detection, Task 5)
    ipAddress: { type: String },
    deviceFingerprint: { type: String },

    failureReason: { type: String, select: false },
  },
  {
    timestamps: true,
    // Transactions are immutable — prevent accidental updates after creation
    statics: {},
  },
);

// Index for efficient user transaction history queries (Task 3 — own-data authorization)
transactionSchema.index({ initiatedBy: 1, createdAt: -1 });
transactionSchema.index({ fromAccount: 1, createdAt: -1 });

const Transaction = mongoose.model('Transaction', transactionSchema);
module.exports = Transaction;
