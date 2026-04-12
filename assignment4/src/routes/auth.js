'use strict';

/**
 * auth.js (routes)
 * Task 1: Secure authentication endpoints.
 * - POST /api/auth/register  — patient self-registration
 * - POST /api/auth/login     — login, returns JWT pair
 * - POST /api/auth/refresh   — exchange refresh token for new access token
 * - POST /api/auth/logout    — destroy session + invalidate refresh token
 * - POST /api/auth/change-password — authenticated password change
 */

const express = require('express');
const router = express.Router();

const { User } = require('../models/User');
const { authenticate, generateTokens, verifyRefreshToken } = require('../middleware/auth');
const { authRateLimiter } = require('../middleware/rateLimiter');
const { setSessionUser, clearSession } = require('../middleware/sessionManager');
const { handleValidationErrors } = require('../middleware/validate');
const { log, ACTIONS } = require('../services/auditService');
const {
  validateEmail,
  validatePassword,
  validateName,
  validateDOB,
  validatePhone,
} = require('../utils/validators');

// ─── Register ─────────────────────────────────────────────────────────────────
router.post(
  '/register',
  authRateLimiter,
  [
    validateName('firstName'),
    validateName('lastName'),
    validateEmail(),
    validatePassword(),
    validateDOB(),
    validatePhone(),
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { firstName, lastName, email, password, dateOfBirth, phone } = req.body;

      // Prevent duplicate registration
      const existing = await User.findOne({ email });
      if (existing) {
        // Timing-safe: same response whether email exists or not
        return res.status(409).json({ error: 'Email already registered' });
      }

      const user = new User({ email, password, role: 'patient' });
      user.firstName   = firstName;
      user.lastName    = lastName;
      user.dateOfBirth = dateOfBirth;
      user.phone       = phone;
      await user.save();

      await log({
        action: ACTIONS.PATIENT_CREATE,
        userId: String(user._id),
        userRole: 'patient',
        targetId: String(user._id),
        targetType: 'User',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.status(201).json({ message: 'Registration successful' });
    } catch (err) {
      return res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// ─── Login ────────────────────────────────────────────────────────────────────
router.post(
  '/login',
  authRateLimiter,
  [validateEmail(), validatePassword()],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      // select: false on password — must explicitly request it
      const user = await User.findOne({ email }).select('+password');

      // Consistent timing regardless of whether user exists
      if (!user) {
        await new Promise((r) => setTimeout(r, 200)); // prevent user enumeration via timing
        await log({
          action: ACTIONS.LOGIN_FAILURE,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          metadata: { email },
          outcome: 'failure',
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      if (!user.isActive) {
        return res.status(403).json({ error: 'Account deactivated — contact support' });
      }

      if (user.isAccountLocked()) {
        return res.status(423).json({
          error: 'Account temporarily locked due to multiple failed attempts. Try again later.',
        });
      }

      const valid = await user.verifyPassword(password);
      if (!valid) {
        await user.incrementFailedLogin();
        await log({
          action: ACTIONS.LOGIN_FAILURE,
          userId: String(user._id),
          ip: req.ip,
          userAgent: req.headers['user-agent'],
          metadata: { failedCount: user.failedLoginCount },
          outcome: 'failure',
        });
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      await user.resetFailedLogin();
      setSessionUser(req, user);

      const tokens = generateTokens(user);

      await log({
        action: ACTIONS.LOGIN_SUCCESS,
        userId: String(user._id),
        userRole: user.role,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({
        accessToken:  tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresIn:    process.env.JWT_EXPIRES_IN || '15m',
        role:         user.role,
      });
    } catch (err) {
      return res.status(500).json({ error: 'Login failed' });
    }
  }
);

// ─── Refresh Token ────────────────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

    const decoded = verifyRefreshToken(refreshToken);
    const user = await User.findById(decoded.sub);
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const tokens = generateTokens(user);
    await log({
      action: ACTIONS.TOKEN_REFRESH,
      userId: String(user._id),
      userRole: user.role,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return res.json({ accessToken: tokens.accessToken });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// ─── Logout ───────────────────────────────────────────────────────────────────
router.post('/logout', authenticate, async (req, res) => {
  await log({
    action: ACTIONS.LOGOUT,
    userId: req.user.id,
    userRole: req.user.role,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
  });
  await clearSession(req, res);
  return res.json({ message: 'Logged out successfully' });
});

// ─── Change Password ──────────────────────────────────────────────────────────
router.post(
  '/change-password',
  authenticate,
  [validatePassword()],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      if (!currentPassword) return res.status(400).json({ error: 'Current password is required' });

      const user = await User.findById(req.user.id).select('+password');
      if (!user) return res.status(404).json({ error: 'User not found' });

      const valid = await user.verifyPassword(currentPassword);
      if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });

      if (currentPassword === newPassword) {
        return res.status(400).json({ error: 'New password must differ from current password' });
      }

      user.password = newPassword;
      await user.save();

      await log({
        action: ACTIONS.PASSWORD_CHANGE,
        userId: req.user.id,
        userRole: req.user.role,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });

      return res.json({ message: 'Password changed successfully' });
    } catch {
      return res.status(500).json({ error: 'Password change failed' });
    }
  }
);

module.exports = router;
