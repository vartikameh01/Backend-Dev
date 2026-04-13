'use strict';

const mongoose = require('mongoose');

/**
 * AuditLog model
 * Append-only record of all security-relevant events.
 * Required for PCI DSS Requirement 10 (audit trails).
 * Written by auditService — never mutated after creation.
 */
const auditLogSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    action: {
      type: String,
      required: true,
      enum: [
        // Auth events
        'login_success', 'login_failure', 'logout', 'lockout',
        'password_reset_request', 'password_reset_complete',
        '2fa_enabled', '2fa_disabled', '2fa_verified', '2fa_failed',
        'device_added', 'suspicious_device',
        // Transaction events
        'transfer_initiated', 'transfer_completed', 'transfer_failed',
        'bill_payment_initiated', 'bill_payment_completed',
        'deposit', 'withdrawal',
        // Account events
        'account_created', 'account_closed',
        'profile_updated',
        'beneficiary_added', 'beneficiary_removed',
        'loan_requested', 'loan_approved', 'loan_rejected',
        // Admin events
        'admin_action',
      ],
    },
    resourceType: { type: String },   // e.g., 'Transaction', 'Account'
    resourceId:   { type: String },   // ID of the affected resource
    ipAddress:    { type: String },
    userAgent:    { type: String },
    deviceFingerprint: { type: String },
    metadata:     { type: mongoose.Schema.Types.Mixed }, // additional event details
    severity:     { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low' },
  },
  {
    timestamps: true,
    // TTL index: retain audit logs for 7 years (PCI DSS Req 10.7)
    // In production, point this at cold storage after 90 days
  },
);

// Ensure logs are never updated (mongoose middleware guard)
auditLogSchema.pre('findOneAndUpdate', function () {
  throw new Error('AuditLog records are immutable');
});
auditLogSchema.pre('updateOne', function () {
  throw new Error('AuditLog records are immutable');
});

const AuditLog = mongoose.model('AuditLog', auditLogSchema);
module.exports = AuditLog;
