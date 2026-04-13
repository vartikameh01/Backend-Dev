'use strict';

const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

/**
 * requireAuth
 * Verifies the JWT access token from the Authorization header.
 * Attaches decoded payload to req.user on success.
 *
 * Fixes: sessions must be validated server-side; simply having a cookie is not enough.
 * Used on all protected routes.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'quickbank',
      audience: 'quickbank-api',
    });
    req.user = payload; // { sub: userId, role, email, iat, exp }
    next();
  } catch (err) {
    logger.warn('JWT verification failed', { error: err.message, ip: req.ip });
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/**
 * requireRole
 * Authorization middleware — restricts endpoint to specific roles.
 * Prevents horizontal privilege escalation.
 *
 * @param {...string} roles - Allowed roles (e.g., 'admin')
 * @returns {function} Express middleware
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!roles.includes(req.user.role)) {
      logger.warn('Unauthorized role access attempt', {
        userId: req.user.sub,
        role: req.user.role,
        requiredRoles: roles,
        path: req.path,
      });
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

/**
 * requireOwnership
 * Ensures the authenticated user owns the resource identified by req.params[paramName].
 * Fixes: "users can only access their own data" (Task 3).
 * Admin role bypasses this check.
 *
 * @param {string} paramName - Route param holding the owner user ID
 * @returns {function} Express middleware
 */
function requireOwnership(paramName = 'userId') {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (req.user.role === 'admin') return next();
    if (req.params[paramName] !== req.user.sub) {
      logger.warn('Ownership check failed', {
        userId: req.user.sub,
        requestedId: req.params[paramName],
        path: req.path,
      });
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
}

/**
 * require2FAVerified
 * For high-value transactions, requires a `x-2fa-token` header with a valid TOTP code
 * that was verified during this request cycle (stored in req.twoFactorVerified).
 * The 2FA verification itself is handled in authService.verify2FA.
 *
 * Used on POST /transactions/transfer and POST /transactions/bill-payment when
 * amountCents exceeds TX_2FA_THRESHOLD_CENTS.
 */
function require2FAVerified(req, res, next) {
  if (!req.twoFactorVerified) {
    return res.status(403).json({
      error: '2FA verification required for this transaction',
      code: '2FA_REQUIRED',
    });
  }
  next();
}

module.exports = { requireAuth, requireRole, requireOwnership, require2FAVerified };
