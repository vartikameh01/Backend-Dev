/**
 * Auth Routes - EduLearn
 * Registration, login, MFA, password reset
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');

const User = require('../models/User');
const { loginLimiter, registerLimiter, passwordResetLimiter } = require('../middleware/rateLimiter');
const { isAuthenticated, isMfaVerified } = require('../middleware/auth');
const logger = require('../utils/logger');
const { sanitizePlainText } = require('../utils/sanitizer');

// ========================
// Input Validators
// ========================
const registerValidator = [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('password')
    .isLength({ min: 12 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .withMessage('Password must be 12+ chars with upper, lower, number, and special character'),
  body('name')
    .trim()
    .isLength({ min: 2, max: 100 })
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Name must be 2-100 characters (letters, spaces, hyphens, apostrophes)'),
  body('role')
    .optional()
    .isIn(['student', 'instructor'])
    .withMessage('Role must be student or instructor')
];

const loginValidator = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty().withMessage('Password required')
];

// ========================
// POST /api/auth/register
// ========================
router.post('/register', registerLimiter, registerValidator, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, role } = req.body;
    const name = sanitizePlainText(req.body.name);

    const existing = await User.findOne({ email });
    if (existing) {
      // Generic message - don't reveal if email exists
      return res.status(409).json({ error: 'Registration failed. Please try a different email.' });
    }

    const user = new User({ email, password, name, role: role || 'student' });
    await user.save();

    logger.audit('USER_REGISTERED', { userId: user._id, role: user.role, ip: req.ip });

    res.status(201).json({
      message: 'Registration successful. Please log in.',
      userId: user._id
    });
  } catch (err) {
    next(err);
  }
});

// ========================
// POST /api/auth/login
// ========================
router.post('/login', loginLimiter, loginValidator, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password +mfaSecret');

    if (!user || !user.isActive) {
      // Constant time response to prevent user enumeration
      await bcryptCompareStub();
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Check account lock
    if (user.isLocked) {
      const lockRemaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
      logger.warn('Login attempt on locked account', { email, ip: req.ip });
      return res.status(423).json({
        error: `Account temporarily locked. Try again in ${lockRemaining} minute(s).`
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await user.handleFailedLogin();
      logger.warn('Failed login attempt', { email, ip: req.ip, attempts: user.loginAttempts + 1 });
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // MFA check for instructors
    if (user.role === 'instructor' && user.mfaEnabled) {
      // Set partial session - requires MFA completion
      req.session.pendingUserId = user._id.toString();
      req.session.pendingRole = user.role;
      return res.status(200).json({ requiresMfa: true, message: 'Enter your MFA code to continue.' });
    }

    // Create session
    await user.handleSuccessfulLogin();
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user._id.toString();
      req.session.role = user.role;
      req.session.mfaVerified = !user.mfaEnabled; // true if MFA not enabled
      req.session.lastActivity = Date.now();

      logger.audit('USER_LOGIN', { userId: user._id, role: user.role, ip: req.ip });
      res.json({ message: 'Login successful', role: user.role });
    });
  } catch (err) {
    next(err);
  }
});

// Stub to prevent timing attacks on user enumeration
async function bcryptCompareStub() {
  const bcrypt = require('bcryptjs');
  await bcrypt.compare('stub', '$2b$12$stubhashforenumerationprotection1234567');
}

// ========================
// POST /api/auth/mfa/verify
// ========================
router.post('/mfa/verify', async (req, res, next) => {
  try {
    const { token } = req.body;
    const pendingUserId = req.session.pendingUserId;

    if (!pendingUserId) {
      return res.status(400).json({ error: 'No pending MFA session.' });
    }

    const user = await User.findById(pendingUserId).select('+mfaSecret');
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const isValid = authenticator.verify({ token, secret: user.mfaSecret });
    if (!isValid) {
      logger.warn('Failed MFA attempt', { userId: pendingUserId, ip: req.ip });
      return res.status(401).json({ error: 'Invalid MFA code.' });
    }

    await user.handleSuccessfulLogin();
    const userId = user._id.toString();
    const role = user.role;

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = userId;
      req.session.role = role;
      req.session.mfaVerified = true;
      req.session.lastActivity = Date.now();

      logger.audit('MFA_VERIFIED', { userId, ip: req.ip });
      res.json({ message: 'MFA verified. Login successful.', role });
    });
  } catch (err) {
    next(err);
  }
});

// ========================
// POST /api/auth/mfa/setup
// ========================
router.post('/mfa/setup', isAuthenticated, async (req, res, next) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(user.email, process.env.MFA_ISSUER || 'EduLearn', secret);
    const qrCodeUrl = await QRCode.toDataURL(otpauth);

    // Store secret temporarily until verified
    user.mfaSecret = secret;
    await user.save();

    res.json({ qrCode: qrCodeUrl, secret, message: 'Scan QR code with your authenticator app, then verify.' });
  } catch (err) {
    next(err);
  }
});

// ========================
// POST /api/auth/mfa/enable
// ========================
router.post('/mfa/enable', isAuthenticated, async (req, res, next) => {
  try {
    const { token } = req.body;
    const user = await User.findById(req.session.userId).select('+mfaSecret');
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const isValid = authenticator.verify({ token, secret: user.mfaSecret });
    if (!isValid) return res.status(400).json({ error: 'Invalid token. MFA setup failed.' });

    user.mfaEnabled = true;
    await user.save();

    logger.audit('MFA_ENABLED', { userId: user._id });
    res.json({ message: 'MFA enabled successfully.' });
  } catch (err) {
    next(err);
  }
});

// ========================
// POST /api/auth/logout
// ========================
router.post('/logout', isAuthenticated, (req, res) => {
  const userId = req.session.userId;
  req.session.destroy((err) => {
    if (err) logger.error('Session destroy error', err);
    res.clearCookie('edulearn.sid');
    logger.audit('USER_LOGOUT', { userId, ip: req.ip });
    res.json({ message: 'Logged out successfully.' });
  });
});

// ========================
// POST /api/auth/forgot-password
// ========================
router.post('/forgot-password', passwordResetLimiter, [
  body('email').isEmail().normalizeEmail()
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const user = await User.findOne({ email: req.body.email });

    // Always return same message to prevent email enumeration
    const genericMsg = { message: 'If that email is registered, a reset link has been sent.' };

    if (!user) return res.json(genericMsg);

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
    await user.save();

    // In production, send email with reset link
    logger.info('Password reset token generated', { userId: user._id });
    // TODO: Send email with: `${process.env.BASE_URL}/reset-password/${resetToken}`

    res.json(genericMsg);
  } catch (err) {
    next(err);
  }
});

// ========================
// POST /api/auth/reset-password/:token
// ========================
router.post('/reset-password/:token', [
  body('password')
    .isLength({ min: 12 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .withMessage('Password must be 12+ chars with upper, lower, number, and special character')
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }  // Token must not be expired
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token.' });
    }

    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    logger.audit('PASSWORD_RESET', { userId: user._id, ip: req.ip });
    res.json({ message: 'Password reset successful. Please log in.' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
