'use strict';

/**
 * rbac.js
 * Task 1: Role-Based Access Control middleware.
 *
 * Roles (least-privilege hierarchy):
 *   patient    — can only access their own data
 *   doctor     — can access own patients' records
 *   nurse      — limited read access to assigned patients
 *   admin      — full access except patient self-management actions
 *   insurance  — read-only access to approved claim-related records
 *
 * Usage:
 *   router.get('/records/:id', authenticate, requireRole('doctor', 'admin'), handler)
 *   router.get('/records/:id', authenticate, requireOwnerOrRole('admin'), handler)
 */

const { ACTIONS, log } = require('../services/auditService');

/**
 * requireRole
 * Allows only users whose role is in the provided list.
 */
function requireRole(...allowedRoles) {
  return async (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    if (!allowedRoles.includes(req.user.role)) {
      await log({
        action: ACTIONS.ACCESS_DENIED,
        userId: req.user.id,
        userRole: req.user.role,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: {
          requiredRoles: allowedRoles,
          path: req.path,
          method: req.method,
        },
        outcome: 'failure',
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    return next();
  };
}

/**
 * requireOwnerOrRole
 * Passes if the authenticated user IS the resource owner (req.params.patientId === req.user.id)
 * OR if their role is in the allowedRoles list.
 * Prevents IDOR attacks by coupling ownership check with role check.
 */
function requireOwnerOrRole(...allowedRoles) {
  return async (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    const resourceOwnerId =
      req.params.patientId ||
      req.params.userId ||
      req.params.id;

    const isOwner = resourceOwnerId && String(resourceOwnerId) === String(req.user.id);
    const hasRole = allowedRoles.includes(req.user.role);

    if (!isOwner && !hasRole) {
      await log({
        action: ACTIONS.ACCESS_DENIED,
        userId: req.user.id,
        userRole: req.user.role,
        targetId: resourceOwnerId,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        metadata: { requiredRoles: allowedRoles, path: req.path, method: req.method },
        outcome: 'failure',
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    return next();
  };
}

/**
 * requirePatientSelf
 * Strict: only the patient themselves can access this resource.
 * Used for endpoints like /patients/:id/insurance.
 */
function requirePatientSelf(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });

  const resourceId = req.params.patientId || req.params.id;
  if (String(resourceId) !== String(req.user.id)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  return next();
}

module.exports = { requireRole, requireOwnerOrRole, requirePatientSelf };
