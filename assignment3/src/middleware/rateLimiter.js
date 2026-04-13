/**
 * Rate Limiting Strategies
 * Different limits for different endpoint types
 */

const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

// Helper to create rate limiters with logging
const createLimiter = (options) => {
  return rateLimit({
    standardHeaders: true,  // Return rate limit info in headers
    legacyHeaders: false,   // Disable X-RateLimit-* headers
    handler: (req, res) => {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        path: req.path,
        limiterName: options.name || 'unknown'
      });
      res.status(429).json({
        error: 'Too many requests. Please try again later.',
        retryAfter: Math.ceil(options.windowMs / 1000)
      });
    },
    ...options
  });
};

/**
 * Login rate limiter - strict
 * 5 attempts per 15 minutes per IP
 */
const loginLimiter = createLimiter({
  name: 'login',
  windowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 5,
  message: { error: 'Too many login attempts. Account temporarily locked. Try again in 15 minutes.' },
  skipSuccessfulRequests: false
});

/**
 * Registration rate limiter
 * 3 accounts per hour per IP
 */
const registerLimiter = createLimiter({
  name: 'register',
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: 'Too many registration attempts. Try again later.' }
});

/**
 * Quiz submission rate limiter
 * 3 submissions per minute per user
 */
const quizSubmitLimiter = createLimiter({
  name: 'quiz-submit',
  windowMs: parseInt(process.env.QUIZ_RATE_LIMIT_WINDOW) || 60 * 1000,
  max: parseInt(process.env.QUIZ_RATE_LIMIT_MAX) || 3,
  keyGenerator: (req) => req.session?.userId || req.ip,
  message: { error: 'Too many quiz submissions. Please wait before trying again.' }
});

/**
 * General API rate limiter
 * 100 requests per 15 minutes per IP
 */
const apiLimiter = createLimiter({
  name: 'api',
  windowMs: parseInt(process.env.API_RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.API_RATE_LIMIT_MAX) || 100
});

/**
 * File upload rate limiter
 * 10 uploads per hour per user
 */
const uploadLimiter = createLimiter({
  name: 'upload',
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.session?.userId || req.ip,
  message: { error: 'Upload limit reached. Try again later.' }
});

/**
 * Password reset rate limiter
 * 3 requests per hour per IP
 */
const passwordResetLimiter = createLimiter({
  name: 'password-reset',
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: 'Too many password reset attempts. Try again later.' }
});

module.exports = {
  loginLimiter,
  registerLimiter,
  quizSubmitLimiter,
  apiLimiter,
  uploadLimiter,
  passwordResetLimiter
};
