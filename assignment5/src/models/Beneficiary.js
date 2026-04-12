'use strict';

const mongoose = require('mongoose');
const { fieldEncryption } = require('mongoose-field-encryption');

/**
 * Beneficiary model
 * Stores saved payees for a user.
 * Account and routing numbers are encrypted at rest.
 * Nickname and bankName are sanitized before storage.
 */
const beneficiarySchema = new mongoose.Schema(
  {
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    nickname: { type: String, required: true, trim: true, maxlength: 50 },
    accountNumber: { type: String, required: true, select: false },
    routingNumber: { type: String, required: true, select: false },
    bankName: { type: String, required: true, trim: true, maxlength: 100 },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true },
);

beneficiarySchema.plugin(fieldEncryption, {
  fields: ['accountNumber', 'routingNumber'],
  secret: process.env.FIELD_ENCRYPTION_KEY || 'fallback-dev-key-32-bytes-exactly!',
  saltGenerator: (secret) => secret.slice(0, 16),
});

const Beneficiary = mongoose.model('Beneficiary', beneficiarySchema);
module.exports = Beneficiary;
