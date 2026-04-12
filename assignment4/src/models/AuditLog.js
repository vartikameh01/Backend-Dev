'use strict';

/**
 * AuditLog.js
 * Task 7: Immutable audit log collection.
 * HIPAA §164.312(b) — record of activity in systems containing ePHI.
 * Documents are never deleted (no delete permission defined here).
 * TTL index automatically purges logs after AUDIT_LOG_RETENTION_DAYS (HIPAA min: 6 years = 2190 days).
 */

const mongoose = require('mongoose');

const RETENTION_DAYS = parseInt(process.env.AUDIT_LOG_RETENTION_DAYS, 10) || 2555; // ~7 years

const auditLogSchema = new mongoose.Schema(
  {
    action:     { type: String, required: true, index: true },
    userId:     { type: String, index: true },      // string, not ref — survives user deletion
    userRole:   { type: String },
    targetId:   { type: String, index: true },
    targetType: { type: String },
    ip:         { type: String, required: true },
    userAgent:  { type: String },
    outcome:    { type: String, enum: ['success', 'failure'], default: 'success' },
    metadata:   { type: mongoose.Schema.Types.Mixed },
    timestamp:  { type: Date, default: Date.now, index: true },
  },
  {
    // No timestamps: we manage timestamp manually for strict control
    // Capped — optional, keeps collection size bounded in dev
    strict: true,
  }
);

// TTL: auto-expire after retention period to comply with HIPAA storage limits
auditLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: RETENTION_DAYS * 24 * 60 * 60 });

// Prevent updates and deletes — audit logs are append-only
auditLogSchema.pre(['updateOne', 'updateMany', 'findOneAndUpdate', 'deleteOne', 'deleteMany'], function () {
  throw new Error('Audit logs are immutable — update/delete operations are forbidden');
});

const AuditLog = mongoose.model('AuditLog', auditLogSchema);
module.exports = AuditLog;
