'use strict';

const express = require('express');
const { body } = require('express-validator');
const authService = require('../services/authService');
const auditService = require('../services/auditService');
const { requireAuth } = require('../middleware/auth');
const { handleValidation } = require('../middleware/validate');
const {
  loginLimiter,
  passwordResetLimiter,
  twoFactorLimiter,
} = require('../middleware/rateLimiter');
const { passwordRules } = require('../utils/validators');

const router = express.Router();

// ─── POST /auth/register ──────────────────────────────────────────────────────
/**
 * Register a new user.
 * Validates email format and enforces password policy.
 */
router.post(
  '/register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('firstName').isLength({ min: 1, max: 50 }).trim().escape(),
    body('lastName').isLength({ min: 1, max: 50 }).trim().escape(),
    passwordRules('password'),
  ],
  handleValidation,
  async (req, res, next) => {
    try {
      const { email, password, firstName, lastName } = req.body;
      const User = require('../models/User');

      const existing = await User.findOne({ email });
      if (existing) {
        // Generic response — don't reveal whether email is registered
        return res.status(201).json({ message: 'If this email is new, your account has been created.' });
      }

      const user = new User({ email, firstName, lastName });
      await user.setPassword(password);
      await user.save();

      await auditService.log({
        userId: user._id,
        action: 'account_created',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        severity: 'low',
      });

      res.status(201).json({ message: 'Account created. Please log in.' });
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /auth/login ─────────────────────────────────────────────────────────
/**
 * Login with email + password.
 * Rate-limited to 5 attempts per 15 minutes per IP (Task 1).
 */
router.post(
  '/login',
  loginLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
  ],
  handleValidation,
  async (req, res, next) => {
    try {
      const result = await authService.login(req.body.email, req.body.password, {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        deviceFingerprint: req.deviceFingerprint,
      });

      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /auth/2fa/setup ─────────────────────────────────────────────────────
/**
 * Begin 2FA setup — returns a setup token and OTPAuth URL for QR display.
 */
router.post('/2fa/setup', requireAuth, async (req, res, next) => {
  try {
    const result = await authService.setup2FA(req.user.sub);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// ─── POST /auth/2fa/enable ────────────────────────────────────────────────────
/**
 * Confirm 2FA setup by verifying the first OTP.
 * Returns one-time backup codes — store them safely.
 */
router.post(
  '/2fa/enable',
  requireAuth,
  twoFactorLimiter,
  [
    body('setupToken').notEmpty(),
    body('otp').isLength({ min: 6, max: 8 }).isAlphanumeric(),
  ],
  handleValidation,
  async (req, res, next) => {
    try {
      const result = await authService.enable2FA(req.user.sub, req.body.setupToken, req.body.otp);
      res.json({ message: '2FA enabled', ...result });
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /auth/2fa/verify ────────────────────────────────────────────────────
/**
 * Verify a 2FA OTP during the login flow (after credential check returned requires2FA=true).
 * On success, issues full access + refresh tokens.
 */
router.post(
  '/2fa/verify',
  twoFactorLimiter,
  [
    body('tempToken').notEmpty(),
    body('otp').isLength({ min: 6, max: 8 }).isAlphanumeric(),
  ],
  handleValidation,
  async (req, res, next) => {
    try {
      const jwt = require('jsonwebtoken');
      let tempPayload;
      try {
        tempPayload = jwt.verify(req.body.tempToken, process.env.JWT_SECRET, {
          issuer: 'quickbank',
          audience: 'quickbank-api',
        });
      } catch {
        return res.status(401).json({ error: 'Invalid or expired temp token' });
      }

      if (tempPayload.stage !== 'await_2fa') {
        return res.status(400).json({ error: 'Invalid token stage' });
      }

      const valid = await authService.verify2FA(tempPayload.sub, req.body.otp, {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });

      if (!valid) {
        return res.status(401).json({ error: 'Invalid OTP' });
      }

      const User = require('../models/User');
      const user = await User.findById(tempPayload.sub);
      if (!user) return res.status(404).json({ error: 'User not found' });

      res.json({
        accessToken: authService.generateAccessToken(user),
        refreshToken: authService.generateRefreshToken(user),
        user: user.toSafeObject(),
      });
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /auth/password-reset/request ───────────────────────────────────────
/**
 * Request a password reset email. Always returns 200 to prevent email enumeration.
 * Rate-limited to 3 requests per hour (Task 1).
 */
router.post(
  '/password-reset/request',
  passwordResetLimiter,
  [body('email').isEmail().normalizeEmail()],
  handleValidation,
  async (req, res, next) => {
    try {
      await authService.requestPasswordReset(req.body.email, {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });
      // Always 200 — don't reveal whether email exists
      res.json({ message: 'If an account with that email exists, a reset link has been sent.' });
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /auth/password-reset/confirm ───────────────────────────────────────
/**
 * Complete password reset using the token from email.
 * Token expires after 15 minutes and is single-use (Task 1).
 */
router.post(
  '/password-reset/confirm',
  [
    body('token').notEmpty().isLength({ min: 64, max: 64 }),
    passwordRules('newPassword'),
  ],
  handleValidation,
  async (req, res, next) => {
    try {
      await authService.resetPassword(req.body.token, req.body.newPassword, {
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
      });
      res.json({ message: 'Password reset successful. Please log in.' });
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /auth/refresh ───────────────────────────────────────────────────────
/**
 * Rotate access token using a valid refresh token.
 */
router.post(
  '/refresh',
  [body('refreshToken').notEmpty()],
  handleValidation,
  async (req, res, next) => {
    try {
      const result = await authService.refreshAccessToken(req.body.refreshToken);
      res.json(result);
    } catch (err) {
      next(err);
    }
  },
);

// ─── POST /auth/logout ────────────────────────────────────────────────────────
/**
 * Logs out the user and records the audit event.
 * JWTs are stateless — client must discard the token.
 * In production, pair with a token blocklist (Redis) for immediate invalidation.
 */
router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    await auditService.log({
      userId: req.user.sub,
      action: 'logout',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      severity: 'low',
    });
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
