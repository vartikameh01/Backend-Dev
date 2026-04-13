'use strict';

const mongoose = require('mongoose');

/**
 * Loan model
 * Represents a loan request lifecycle.
 */
const loanSchema = new mongoose.Schema(
  {
    applicant: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    linkedAccount: { type: mongoose.Schema.Types.ObjectId, ref: 'Account' },

    principalCents: { type: Number, required: true, min: 10000 }, // min $100
    termMonths:     { type: Number, required: true, min: 1, max: 360 },
    interestRateBps: { type: Number, required: true }, // basis points, e.g. 500 = 5.00%
    purpose: { type: String, maxlength: 200 },

    status: {
      type: String,
      enum: ['pending', 'under_review', 'approved', 'rejected', 'disbursed', 'closed'],
      default: 'pending',
    },

    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reviewNotes: { type: String, maxlength: 1000, select: false },
    reviewedAt: { type: Date },
  },
  { timestamps: true },
);

const Loan = mongoose.model('Loan', loanSchema);
module.exports = Loan;
