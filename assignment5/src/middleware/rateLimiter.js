'use strict';

const rateLimit = require('express-rate-limit');

/**
 * buildLimiter
 * Factory that creates express-rate-limit instances.
 * In-memory store used here; swap for rate-limit-mongo in multi-instance deployments.
 *
 * @param {object} opts - windowMs, max, message
 * @returns {function} Express middleware
 */
function buildLimiter({ windowMs, max, message }) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,  // Return RateLimit-* headers
    legacyHeaders: false,
    message: { error: message },
    skipSuccessfulRequests: false,
    handler: (req, res, next, options) => {
      res.status(429).json({ error: options.message.error });
    },
  });
}

/**
 * loginLimiter
 * 5 attempts per 15 minutes per IP.
 * Fixes the "unlimited login attempts" vulnerability (Task 1).
 */
const loginLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts. Please try again in 15 minutes.',
});

/**
 * passwordResetLimiter
 * 3 reset requests per hour per IP.
 */
const passwordResetLimiter = buildLimiter({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: 'Too many password reset requests. Please try again in an hour.',
});

/**
 * transferLimiter
 * 10 transfers per minute per IP — blocks automated transfer attacks (Task 2).
 */
const transferLimiter = buildLimiter({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Transfer rate limit exceeded. Please slow down.',
});

/**
 * billPaymentLimiter
 * 20 bill payments per 10 minutes per IP.
 */
const billPaymentLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: 'Bill payment rate limit exceeded.',
});

/**
 * generalApiLimiter
 * 200 requests per 15 minutes — general API protection.
 */
const generalApiLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests. Please slow down.',
});

/**
 * twoFactorLimiter
 * 5 OTP attempts per 10 minutes — prevents TOTP brute force.
 */
const twoFactorLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: 'Too many 2FA attempts. Please try again in 10 minutes.',
});

module.exports = {
  loginLimiter,
  passwordResetLimiter,
  transferLimiter,
  billPaymentLimiter,
  generalApiLimiter,
  twoFactorLimiter,
};
