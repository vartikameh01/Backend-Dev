'use strict';

const logger = require('../utils/logger');

/**
 * errorHandler
 * Central Express error handler.
 * CRITICAL: Never leaks stack traces, database errors, or query details to clients.
 * Fixes the "detailed error messages reveal database structure" vulnerability (Task 6).
 *
 * Logged server-side with full detail; client receives only a generic message.
 */
function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  const requestId = req.id || 'unknown';

  // Log full error server-side for debugging
  logger.error('Unhandled error', {
    requestId,
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    userId: req.user?.sub,
  });

  // Mongoose validation error — safe to surface field names
  if (err.name === 'ValidationError') {
    return res.status(422).json({
      error: 'Validation failed',
      details: Object.values(err.errors).map((e) => ({
        field: e.path,
        message: e.message,
      })),
    });
  }

  // JWT errors — already handled in requireAuth, but catch any that leak here
  if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // MongoDB duplicate key — safe to say "already exists", never reveal the key
  if (err.code === 11000) {
    return res.status(409).json({ error: 'A record with that value already exists' });
  }

  // Generic 500 — no internal details
  const statusCode = err.statusCode || err.status || 500;
  const safeStatus = statusCode >= 400 && statusCode < 600 ? statusCode : 500;

  // Only return the error message for client errors (4xx); 5xx gets a generic message
  const clientMessage =
    safeStatus < 500
      ? (err.clientMessage || err.message || 'Request failed')
      : 'An internal error occurred. Please try again later.';

  res.status(safeStatus).json({ error: clientMessage });
}

/**
 * notFound
 * 404 handler — placed before errorHandler in the middleware chain.
 */
function notFound(req, res) {
  res.status(404).json({ error: 'Endpoint not found' });
}

module.exports = { errorHandler, notFound };
