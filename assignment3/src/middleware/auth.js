/**
 * Authentication & Authorization Middleware
 * Role-based access control: Student, Instructor, Admin
 */

const logger = require('../utils/logger');

/**
 * Verify user is authenticated
 */
const isAuthenticated = (req, res, next) => {
  if (!req.session || !req.session.userId) {
    logger.warn('Unauthenticated access attempt', {
      ip: req.ip,
      path: req.path,
      method: req.method
    });
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }

  // Check session freshness (re-auth after 30 min of inactivity)
  const lastActivity = req.session.lastActivity || 0;
  const inactivityLimit = 30 * 60 * 1000; // 30 minutes

  if (Date.now() - lastActivity > inactivityLimit) {
    req.session.destroy((err) => {
      if (err) logger.error('Session destruction error:', err);
    });
    return res.status(401).json({ error: 'Session expired due to inactivity. Please log in again.' });
  }

  // Update last activity
  req.session.lastActivity = Date.now();
  next();
};

/**
 * Verify MFA is completed for instructors
 */
const isMfaVerified = (req, res, next) => {
  if (req.session.role === 'instructor' && !req.session.mfaVerified) {
    return res.status(403).json({ error: 'MFA verification required.' });
  }
  next();
};

/**
 * Role-based authorization
 * @param  {...string} roles - Allowed roles
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.session || !req.session.role) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    if (!roles.includes(req.session.role)) {
      logger.warn('Unauthorized access attempt', {
        userId: req.session.userId,
        role: req.session.role,
        requiredRoles: roles,
        path: req.path
      });
      return res.status(403).json({ error: 'You do not have permission to perform this action.' });
    }

    next();
  };
};

/**
 * Verify resource ownership (user can only access their own resources)
 * @param {Function} getResourceOwnerId - Function that returns the owner ID from the request
 */
const isOwnerOrAdmin = (getResourceOwnerId) => {
  return async (req, res, next) => {
    try {
      const ownerId = await getResourceOwnerId(req);

      if (!ownerId) {
        return res.status(404).json({ error: 'Resource not found.' });
      }

      if (req.session.userId !== ownerId.toString() && req.session.role !== 'admin') {
        logger.warn('Ownership violation attempt', {
          userId: req.session.userId,
          resourceOwnerId: ownerId,
          path: req.path
        });
        return res.status(403).json({ error: 'You do not have permission to access this resource.' });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

module.exports = {
  isAuthenticated,
  isMfaVerified,
  authorize,
  isOwnerOrAdmin
};
