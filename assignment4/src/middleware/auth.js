'use strict';

/**
 * auth.js
 * Task 1: JWT authentication middleware.
 * - Validates Bearer token from Authorization header
 * - Attaches decoded user payload to req.user
 * - Rejects expired, tampered, or missing tokens with 401
 */

const jwt = require('jsonwebtoken');
const { ACTIONS, log } = require('../services/auditService');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ALGORITHM = 'HS256';

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('JWT_SECRET must be at least 32 characters');
  }
}

/**
 * authenticate
 * Express middleware — extracts and verifies the JWT.
 * Attaches { id, role, email } to req.user on success.
 */
async function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
    req.user = {
      id:    decoded.sub,
      role:  decoded.role,
      email: decoded.email,
    };
    return next();
  } catch (err) {
    const isExpired = err.name === 'TokenExpiredError';
    await log({
      action: ACTIONS.ACCESS_DENIED,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      metadata: { reason: isExpired ? 'token_expired' : 'invalid_token', path: req.path },
      outcome: 'failure',
    });
    return res.status(401).json({
      error: isExpired ? 'Session expired — please log in again' : 'Invalid authentication token',
    });
  }
}

/**
 * generateTokens
 * Returns an { accessToken, refreshToken } pair.
 * Access token: short-lived (15 min default) for API calls.
 * Refresh token: longer-lived (8 h default) for session renewal.
 */
function generateTokens(user) {
  const payload = { sub: String(user._id), role: user.role, email: user.email };

  const accessToken = jwt.sign(payload, JWT_SECRET, {
    algorithm: JWT_ALGORITHM,
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
  });

  const refreshToken = jwt.sign(
    { sub: String(user._id), type: 'refresh' },
    JWT_SECRET,
    {
      algorithm: JWT_ALGORITHM,
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '8h',
    }
  );

  return { accessToken, refreshToken };
}

/**
 * verifyRefreshToken
 * Validates a refresh token and returns the decoded payload.
 */
function verifyRefreshToken(token) {
  const decoded = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
  if (decoded.type !== 'refresh') throw new Error('Not a refresh token');
  return decoded;
}

module.exports = { authenticate, generateTokens, verifyRefreshToken };
