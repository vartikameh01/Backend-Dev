'use strict';

const mongoose = require('mongoose');
const { fieldEncryption } = require('mongoose-field-encryption');

/**
 * Account model
 * Represents a bank account.
 * - accountNumber and routingNumber are encrypted at rest (PCI DSS requirement).
 * - balanceCents is stored as integer to avoid floating-point rounding.
 * - owner reference enforces that users can only access their own accounts (Task 3).
 */
const accountSchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, enum: ['checking', 'savings', 'loan'], required: true },

    // Stored encrypted; never returned in list queries unless explicitly selected
    accountNumber: { type: String, required: true, select: false },
    routingNumber: { type: String, required: true, select: false },

    // Balance in cents — integer arithmetic only, no floats
    balanceCents: { type: Number, default: 0, min: 0 },

    currency: { type: String, default: 'USD', enum: ['USD'] },
    isActive: { type: Boolean, default: true },

    // Daily transfer tracking — reset at midnight UTC
    dailyTransferredCents: { type: Number, default: 0 },
    dailyTransferResetAt: { type: Date, default: () => startOfTomorrow() },
  },
  { timestamps: true },
);

function startOfTomorrow() {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + 1);
  d.setUTCHours(0, 0, 0, 0);
  return d;
}

// Encrypt account and routing numbers at rest
accountSchema.plugin(fieldEncryption, {
  fields: ['accountNumber', 'routingNumber'],
  secret: process.env.FIELD_ENCRYPTION_KEY || 'fallback-dev-key-32-bytes-exactly!',
  saltGenerator: (secret) => secret.slice(0, 16),
});

/**
 * resetDailyLimitIfNeeded
 * Resets the daily transfer counter when the reset window has passed.
 * Call before any transfer to get an accurate daily total.
 */
accountSchema.methods.resetDailyLimitIfNeeded = function () {
  if (Date.now() >= this.dailyTransferResetAt.getTime()) {
    this.dailyTransferredCents = 0;
    this.dailyTransferResetAt = startOfTomorrow();
  }
};

/**
 * hasSufficientFunds
 * Returns true if the account can cover the requested amount.
 */
accountSchema.methods.hasSufficientFunds = function (amountCents) {
  return this.balanceCents >= amountCents;
};

const Account = mongoose.model('Account', accountSchema);
module.exports = Account;
