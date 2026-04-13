'use strict';

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

/**
 * auditService.log
 * Creates an immutable audit log entry.
 * Called by middleware, routes, and services for every security-relevant event.
 * Implements Task 5 — comprehensive logging and monitoring.
 *
 * @param {object} params
 * @param {string|ObjectId} params.userId
 * @param {string} params.action         - AuditLog.action enum value
 * @param {string} [params.resourceType]
 * @param {string} [params.resourceId]
 * @param {string} [params.ipAddress]
 * @param {string} [params.userAgent]
 * @param {string} [params.deviceFingerprint]
 * @param {object} [params.metadata]
 * @param {string} [params.severity]     - 'low'|'medium'|'high'|'critical'
 */
async function log(params) {
  try {
    await AuditLog.create(params);
  } catch (err) {
    // Audit log failures must not break the application flow — but must be loudly logged
    logger.error('AUDIT LOG WRITE FAILURE', { error: err.message, params });
  }
}

/**
 * auditService.getFailedLogins
 * Retrieves failed login events for a user within a time window.
 * Used by fraudDetectionService to assess brute-force patterns.
 *
 * @param {string} userId
 * @param {number} windowMs
 * @returns {Promise<AuditLog[]>}
 */
async function getFailedLogins(userId, windowMs = 60 * 60 * 1000) {
  const since = new Date(Date.now() - windowMs);
  return AuditLog.find({
    userId,
    action: 'login_failure',
    createdAt: { $gte: since },
  })
    .sort({ createdAt: -1 })
    .limit(50)
    .lean();
}

/**
 * auditService.getTransactionHistory
 * Returns audit log entries related to financial operations for a specific user.
 * Note: actual transaction data is in the Transaction model;
 * this returns the security event log view.
 *
 * @param {string} userId
 * @param {object} [filter]
 * @returns {Promise<AuditLog[]>}
 */
async function getTransactionHistory(userId, { page = 1, limit = 20 } = {}) {
  const skip = (page - 1) * limit;
  return AuditLog.find({
    userId,
    action: { $in: ['transfer_initiated', 'transfer_completed', 'bill_payment_completed', 'deposit', 'withdrawal'] },
  })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
}

module.exports = { log, getFailedLogins, getTransactionHistory };
