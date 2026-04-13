'use strict';

/**
 * rateLimiter.js
 * Task 1: Rate limiting to protect against brute-force and DoS attacks.
 *
 * Three tiers:
 *  1. globalRateLimiter     — all routes (loose, anti-DoS)
 *  2. authRateLimiter       — /api/auth/login and /api/auth/register (strict)
 *  3. sensitiveRateLimiter  — PHI endpoints (medium)
 */

const rateLimit = require('express-rate-limit');

const WINDOW_MS   = parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000; // 15 min
const GLOBAL_MAX  = parseInt(process.env.RATE_LIMIT_MAX, 10) || 100;
const AUTH_MAX    = parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 5;
const SENSITIVE_MAX = 30;

// Standard headers (RateLimit-*) — NOT the legacy X-RateLimit-* headers
const commonOptions = {
  standardHeaders: true,
  legacyHeaders: false,
  // Return JSON error body
  handler: (_req, res) => {
    res.status(429).json({
      error: 'Too many requests — please try again later',
    });
  },
};

/**
 * globalRateLimiter
 * Applies to every request. Loose limit to prevent volumetric DoS.
 */
const globalRateLimiter = rateLimit({
  ...commonOptions,
  windowMs: WINDOW_MS,
  max: GLOBAL_MAX,
  message: 'Too many requests from this IP',
});

/**
 * authRateLimiter
 * Strict limit on authentication endpoints to prevent credential stuffing
 * and brute-force attacks. 5 attempts per 15 minutes per IP.
 */
const authRateLimiter = rateLimit({
  ...commonOptions,
  windowMs: WINDOW_MS,
  max: AUTH_MAX,
  skipSuccessfulRequests: true, // Only count failed requests toward the limit
});

/**
 * sensitiveRateLimiter
 * Applied to PHI endpoints (medical records, prescriptions, documents).
 * Stricter than global but looser than auth.
 */
const sensitiveRateLimiter = rateLimit({
  ...commonOptions,
  windowMs: WINDOW_MS,
  max: SENSITIVE_MAX,
});

module.exports = { globalRateLimiter, authRateLimiter, sensitiveRateLimiter };
