'use strict';

const auditService = require('../services/auditService');
const logger = require('../utils/logger');

/**
 * auditTransaction
 * Express middleware factory that writes a financial audit log entry
 * after a transaction route has responded successfully.
 * Meets PCI DSS Requirement 10 — audit trail for all financial transactions (Task 5).
 *
 * @param {string} action - AuditLog action enum value
 * @returns {function} Express middleware
 */
function auditTransaction(action) {
  return (req, res, next) => {
    // Capture the original json() so we can observe the response body
    const originalJson = res.json.bind(res);
    res.json = function (body) {
      // Only log on success (2xx)
      if (res.statusCode >= 200 && res.statusCode < 300 && req.user) {
        auditService
          .log({
            userId: req.user.sub,
            action,
            resourceType: 'Transaction',
            resourceId: body?.data?.transactionId || body?.data?._id,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            deviceFingerprint: req.deviceFingerprint,
            metadata: {
              amountCents: req.body?.amountCents,
              fromAccount: req.body?.fromAccountId,
              toAccount: req.body?.toAccountId,
            },
            severity: 'high',
          })
          .catch((err) => logger.error('Audit log write failed', { error: err.message }));
      }
      return originalJson(body);
    };
    next();
  };
}

/**
 * auditProfileUpdate
 * Logs profile/account changes for GDPR and PCI DSS compliance.
 */
function auditProfileUpdate(req, res, next) {
  const originalJson = res.json.bind(res);
  res.json = function (body) {
    if (res.statusCode >= 200 && res.statusCode < 300 && req.user) {
      auditService
        .log({
          userId: req.user.sub,
          action: 'profile_updated',
          resourceType: 'User',
          resourceId: req.user.sub,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
          metadata: { fieldsChanged: Object.keys(req.body || {}) },
          severity: 'medium',
        })
        .catch((err) => logger.error('Profile audit log write failed', { error: err.message }));
    }
    return originalJson(body);
  };
  next();
}

module.exports = { auditTransaction, auditProfileUpdate };
