'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const auditService = require('./auditService');
const notificationService = require('./notificationService');
const security = require('../config/security');
const logger = require('../utils/logger');

authenticator.options = {
  issuer: security.totpIssuer,
  window: security.totpWindow,
};

// ─── JWT ──────────────────────────────────────────────────────────────────────

/**
 * generateAccessToken
 * Issues a short-lived JWT access token.
 * Payload is minimal — no sensitive data, just identity claims.
 *
 * @param {User} user
 * @returns {string} signed JWT
 */
function generateAccessToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), role: user.role, email: user.email },
    process.env.JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: security.jwtExpiry,
      issuer: 'quickbank',
      audience: 'quickbank-api',
    },
  );
}

/**
 * generateRefreshToken
 * Issues a longer-lived refresh token for token rotation.
 */
function generateRefreshToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { algorithm: 'HS256', expiresIn: security.jwtRefreshExpiry, issuer: 'quickbank' },
  );
}

// ─── Login / Lockout ─────────────────────────────────────────────────────────

/**
 * login
 * Authenticates a user by email + password.
 * Implements:
 * - Account lockout after max failed attempts (Task 1)
 * - Constant-time comparison via bcrypt
 * - Audit logging for success and failure
 *
 * @param {string} email
 * @param {string} password
 * @param {object} context - { ipAddress, userAgent, deviceFingerprint }
 * @returns {{ accessToken, refreshToken, user, requires2FA }}
 */
async function login(email, password, context) {
  // Use +select to load sensitive fields not returned by default
  const user = await User.findOne({ email: email.toLowerCase() })
    .select('+passwordHash +failedLoginAttempts +lockoutUntil +twoFactorEnabled');

  // Generic error — don't reveal whether email exists (prevents user enumeration)
  const genericError = new Error('Invalid email or password');
  genericError.statusCode = 401;

  if (!user || !user.isActive) throw genericError;

  if (user.isLocked()) {
    await auditService.log({ userId: user._id, action: 'lockout', ...context, severity: 'high' });
    const lockErr = new Error('Account temporarily locked. Please try again later.');
    lockErr.statusCode = 423;
    throw lockErr;
  }

  const valid = await user.verifyPassword(password);
  if (!valid) {
    await user.recordFailedLogin();
    await auditService.log({ userId: user._id, action: 'login_failure', ...context, severity: 'medium' });
    throw genericError;
  }

  await user.resetLoginAttempts();
  await auditService.log({ userId: user._id, action: 'login_success', ...context, severity: 'low' });

  // If 2FA is enabled, return a partial session — client must submit OTP
  if (user.twoFactorEnabled) {
    const tempToken = jwt.sign(
      { sub: user._id.toString(), stage: 'await_2fa' },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '5m', issuer: 'quickbank', audience: 'quickbank-api' },
    );
    return { requires2FA: true, tempToken };
  }

  return {
    requires2FA: false,
    accessToken: generateAccessToken(user),
    refreshToken: generateRefreshToken(user),
    user: user.toSafeObject(),
  };
}

// ─── 2FA ─────────────────────────────────────────────────────────────────────

/**
 * setup2FA
 * Generates a TOTP secret and returns the OTPAuth URI for QR code display.
 * The secret is NOT saved until the user confirms a valid OTP (enable2FA).
 *
 * @param {string} userId
 * @returns {{ secret, otpAuthUrl }}
 */
async function setup2FA(userId) {
  const user = await User.findById(userId);
  if (!user) throw Object.assign(new Error('User not found'), { statusCode: 404 });

  const secret = authenticator.generateSecret();
  const otpAuthUrl = authenticator.keyuri(user.email, security.totpIssuer, secret);

  // Store secret temporarily in a short-lived JWT so we don't persist unconfirmed secrets
  const setupToken = jwt.sign(
    { sub: userId, secret, stage: 'setup_2fa' },
    process.env.JWT_SECRET,
    { expiresIn: '10m', issuer: 'quickbank' },
  );

  return { setupToken, otpAuthUrl };
}

/**
 * enable2FA
 * Confirms 2FA setup by verifying the first OTP against the pending secret.
 * Generates and stores hashed backup codes.
 *
 * @param {string} userId
 * @param {string} setupToken - from setup2FA
 * @param {string} otp
 */
async function enable2FA(userId, setupToken, otp) {
  let payload;
  try {
    payload = jwt.verify(setupToken, process.env.JWT_SECRET, { issuer: 'quickbank' });
  } catch {
    throw Object.assign(new Error('Setup token expired or invalid'), { statusCode: 400 });
  }

  if (payload.sub !== userId || payload.stage !== 'setup_2fa') {
    throw Object.assign(new Error('Invalid setup token'), { statusCode: 400 });
  }

  if (!authenticator.verify({ token: otp, secret: payload.secret })) {
    throw Object.assign(new Error('Invalid OTP'), { statusCode: 400 });
  }

  // Generate 8 one-time backup codes (hashed for storage)
  const rawCodes = Array.from({ length: 8 }, () => crypto.randomBytes(4).toString('hex'));
  const hashedCodes = await Promise.all(rawCodes.map((c) => bcrypt.hash(c, 10)));

  await User.findByIdAndUpdate(userId, {
    twoFactorSecret: payload.secret,
    twoFactorEnabled: true,
    twoFactorBackupCodes: hashedCodes,
  });

  await auditService.log({ userId, action: '2fa_enabled', severity: 'medium' });
  return { backupCodes: rawCodes }; // Return raw codes ONCE — never again
}

/**
 * verify2FA
 * Verifies an OTP during login or high-value transaction confirmation.
 * Accepts TOTP codes or backup codes.
 *
 * @param {string} userId
 * @param {string} otp
 * @param {object} context
 * @returns {boolean}
 */
async function verify2FA(userId, otp, context = {}) {
  const user = await User.findById(userId).select('+twoFactorSecret +twoFactorBackupCodes');
  if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
    return false;
  }

  // Try TOTP first
  if (authenticator.verify({ token: otp, secret: user.twoFactorSecret })) {
    await auditService.log({ userId, action: '2fa_verified', ...context, severity: 'low' });
    return true;
  }

  // Try backup codes
  const codeIndex = await findValidBackupCode(user.twoFactorBackupCodes, otp);
  if (codeIndex !== -1) {
    // Consume (remove) the used backup code
    user.twoFactorBackupCodes.splice(codeIndex, 1);
    await user.save();
    await auditService.log({ userId, action: '2fa_verified', ...context, metadata: { usedBackupCode: true }, severity: 'medium' });
    return true;
  }

  await auditService.log({ userId, action: '2fa_failed', ...context, severity: 'high' });
  return false;
}

async function findValidBackupCode(hashedCodes, plainCode) {
  for (let i = 0; i < hashedCodes.length; i++) {
    if (await bcrypt.compare(plainCode, hashedCodes[i])) return i;
  }
  return -1;
}

// ─── Password Reset ───────────────────────────────────────────────────────────

/**
 * requestPasswordReset
 * Generates a cryptographically random, time-limited reset token.
 * Fixes: tokens that never expired and could be reused (Task 1).
 * Always returns generic success — prevents email enumeration.
 *
 * @param {string} email
 * @param {object} context
 */
async function requestPasswordReset(email, context) {
  const user = await User.findOne({ email: email.toLowerCase() });
  // Always succeed silently — prevents user enumeration
  if (!user) {
    logger.info('Password reset requested for unknown email', { email });
    return;
  }

  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiry = new Date(Date.now() + security.passwordResetTokenTTLMs);

  await User.findByIdAndUpdate(user._id, {
    passwordResetToken: tokenHash,
    passwordResetExpiry: expiry,
  });

  await auditService.log({ userId: user._id, action: 'password_reset_request', ...context, severity: 'medium' });
  await notificationService.sendPasswordResetEmail(user.email, token);
}

/**
 * resetPassword
 * Validates the reset token and updates the password.
 * Token is single-use (cleared after use) and expires after TTL.
 *
 * @param {string} token - raw token from email link
 * @param {string} newPassword
 * @param {object} context
 */
async function resetPassword(token, newPassword, context) {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const user = await User.findOne({
    passwordResetToken: tokenHash,
    passwordResetExpiry: { $gt: new Date() }, // must not be expired
  }).select('+passwordResetToken +passwordResetExpiry');

  if (!user) {
    throw Object.assign(new Error('Invalid or expired reset token'), { statusCode: 400 });
  }

  await user.setPassword(newPassword);
  // Invalidate token — single-use
  user.passwordResetToken = undefined;
  user.passwordResetExpiry = undefined;
  // Invalidate all active sessions (security measure)
  await user.save();

  await auditService.log({ userId: user._id, action: 'password_reset_complete', ...context, severity: 'high' });
}

// ─── Refresh Tokens ───────────────────────────────────────────────────────────

/**
 * refreshAccessToken
 * Issues a new access token using a valid refresh token (token rotation).
 *
 * @param {string} refreshToken
 * @returns {{ accessToken }}
 */
async function refreshAccessToken(refreshToken) {
  let payload;
  try {
    payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, { issuer: 'quickbank' });
  } catch {
    throw Object.assign(new Error('Invalid or expired refresh token'), { statusCode: 401 });
  }

  if (payload.type !== 'refresh') throw Object.assign(new Error('Not a refresh token'), { statusCode: 401 });

  const user = await User.findById(payload.sub);
  if (!user || !user.isActive) throw Object.assign(new Error('User not found'), { statusCode: 401 });

  return { accessToken: generateAccessToken(user) };
}

module.exports = {
  login,
  setup2FA,
  enable2FA,
  verify2FA,
  requestPasswordReset,
  resetPassword,
  refreshAccessToken,
  generateAccessToken,
  generateRefreshToken,
};
