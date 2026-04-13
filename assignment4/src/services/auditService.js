'use strict';

/**
 * auditService.js
 * Task 7: Comprehensive HIPAA-compliant audit log service.
 *
 * HIPAA §164.312(b) requires audit controls — records of activity on
 * systems containing ePHI. Every access, modification, or deletion of
 * medical records must be logged with: who, what, when, where, outcome.
 */

const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

// ─── Action constants ─────────────────────────────────────────────────────────
const ACTIONS = {
  // Auth events
  LOGIN_SUCCESS: 'AUTH_LOGIN_SUCCESS',
  LOGIN_FAILURE: 'AUTH_LOGIN_FAILURE',
  LOGOUT: 'AUTH_LOGOUT',
  PASSWORD_CHANGE: 'AUTH_PASSWORD_CHANGE',
  TOKEN_REFRESH: 'AUTH_TOKEN_REFRESH',
  // Patient PHI events
  PATIENT_VIEW: 'PATIENT_VIEW',
  PATIENT_CREATE: 'PATIENT_CREATE',
  PATIENT_UPDATE: 'PATIENT_UPDATE',
  PATIENT_DELETE: 'PATIENT_DELETE',
  // Medical record events
  RECORD_VIEW: 'MEDICAL_RECORD_VIEW',
  RECORD_CREATE: 'MEDICAL_RECORD_CREATE',
  RECORD_UPDATE: 'MEDICAL_RECORD_UPDATE',
  RECORD_DELETE: 'MEDICAL_RECORD_DELETE',
  // Document events
  DOCUMENT_UPLOAD: 'DOCUMENT_UPLOAD',
  DOCUMENT_VIEW: 'DOCUMENT_VIEW',
  DOCUMENT_DELETE: 'DOCUMENT_DELETE',
  // Appointment events
  APPOINTMENT_CREATE: 'APPOINTMENT_CREATE',
  APPOINTMENT_VIEW: 'APPOINTMENT_VIEW',
  APPOINTMENT_UPDATE: 'APPOINTMENT_UPDATE',
  APPOINTMENT_CANCEL: 'APPOINTMENT_CANCEL',
  // Prescription events
  PRESCRIPTION_CREATE: 'PRESCRIPTION_CREATE',
  PRESCRIPTION_VIEW: 'PRESCRIPTION_VIEW',
  // Security events
  ACCESS_DENIED: 'SECURITY_ACCESS_DENIED',
  INJECTION_ATTEMPT: 'SECURITY_INJECTION_ATTEMPT',
  RATE_LIMIT_EXCEEDED: 'SECURITY_RATE_LIMIT_EXCEEDED',
};

/**
 * log
 * Persists an audit entry. Falls back to Winston if DB write fails
 * so a DB outage never silently loses audit records.
 *
 * @param {object} params
 * @param {string} params.action      - ACTIONS constant
 * @param {string} [params.userId]    - performing user's _id
 * @param {string} [params.userRole]  - role at time of action
 * @param {string} [params.targetId]  - resource being acted on
 * @param {string} [params.targetType]- 'Patient' | 'MedicalRecord' | etc.
 * @param {string} params.ip          - client IP address
 * @param {string} [params.userAgent] - User-Agent header
 * @param {object} [params.metadata]  - extra context (no raw PHI)
 * @param {string} [params.outcome]   - 'success' | 'failure'
 */
async function log({
  action,
  userId = null,
  userRole = null,
  targetId = null,
  targetType = null,
  ip,
  userAgent = '',
  metadata = {},
  outcome = 'success',
}) {
  const entry = {
    action,
    userId,
    userRole,
    targetId,
    targetType,
    ip,
    userAgent,
    metadata,
    outcome,
    timestamp: new Date(),
  };

  try {
    await AuditLog.create(entry);
  } catch (dbErr) {
    // Failsafe: always write to file logger so audit is never silently lost
    logger.error('Audit DB write failed — falling back to file log', {
      auditEntry: entry,
      dbError: dbErr.message,
    });
  }
}

/**
 * query
 * Retrieve audit logs for compliance reporting.
 * Supports filters by userId, action, targetId, and date range.
 * Results are sorted newest-first and paginated.
 */
async function query({ userId, action, targetId, startDate, endDate, page = 1, limit = 50 } = {}) {
  const filter = {};
  if (userId) filter.userId = userId;
  if (action) filter.action = action;
  if (targetId) filter.targetId = String(targetId);
  if (startDate || endDate) {
    filter.timestamp = {};
    if (startDate) filter.timestamp.$gte = new Date(startDate);
    if (endDate) filter.timestamp.$lte = new Date(endDate);
  }

  const skip = (page - 1) * limit;
  const [records, total] = await Promise.all([
    AuditLog.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).lean(),
    AuditLog.countDocuments(filter),
  ]);

  return { records, total, page, pages: Math.ceil(total / limit) };
}

module.exports = { log, query, ACTIONS };
