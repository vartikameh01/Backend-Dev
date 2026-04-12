'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { fieldEncryption } = require('mongoose-field-encryption');
const security = require('../config/security');

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email format'],
    },
    passwordHash: { type: String, required: true, select: false },

    firstName: { type: String, required: true, trim: true, maxlength: 50 },
    lastName:  { type: String, required: true, trim: true, maxlength: 50 },

    // Phone stored encrypted at rest
    phone: { type: String, trim: true },

    // Encrypted national ID / SSN last 4 — stored encrypted, never returned by default
    ssnLast4: { type: String, select: false },

    role: { type: String, enum: ['customer', 'admin'], default: 'customer' },
    isActive: { type: Boolean, default: true },
    isEmailVerified: { type: Boolean, default: false },

    // Two-factor authentication
    twoFactorSecret: { type: String, select: false },        // TOTP secret (encrypted)
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorBackupCodes: { type: [String], select: false }, // hashed backup codes

    // Biometric auth (mobile) — stores a credential ID reference only, not the key itself
    biometricCredentialId: { type: String, select: false },

    // Brute-force lockout (Task 1 — secure login)
    failedLoginAttempts: { type: Number, default: 0, select: false },
    lockoutUntil: { type: Date, default: null, select: false },

    // Password reset (Task 1 — expiring tokens)
    passwordResetToken: { type: String, select: false },
    passwordResetExpiry: { type: Date, select: false },

    // Device fingerprinting (Task 1 — suspicious activity)
    knownDevices: {
      type: [
        {
          fingerprint: String,
          userAgent: String,
          ip: String,
          firstSeen: { type: Date, default: Date.now },
          lastSeen: { type: Date, default: Date.now },
        },
      ],
      select: false,
      default: [],
    },

    // Notification preferences
    emailNotifications: { type: Boolean, default: true },
  },
  { timestamps: true },
);

// Encrypt sensitive fields at rest using mongoose-field-encryption
userSchema.plugin(fieldEncryption, {
  fields: ['phone', 'ssnLast4', 'twoFactorSecret'],
  secret: process.env.FIELD_ENCRYPTION_KEY || 'fallback-dev-key-32-bytes-exactly!',
  saltGenerator: (secret) => secret.slice(0, 16),
});

// ─── Instance Methods ───────────────────────────────────────────────────────

/**
 * setPassword
 * Hashes and stores a new password. Call this instead of setting passwordHash directly.
 */
userSchema.methods.setPassword = async function (plainText) {
  this.passwordHash = await bcrypt.hash(plainText, security.bcryptRounds);
};

/**
 * verifyPassword
 * Constant-time comparison to prevent timing attacks.
 */
userSchema.methods.verifyPassword = async function (plainText) {
  return bcrypt.compare(plainText, this.passwordHash);
};

/**
 * isLocked
 * Returns true when the account is in the lockout window.
 */
userSchema.methods.isLocked = function () {
  return this.lockoutUntil && this.lockoutUntil > Date.now();
};

/**
 * recordFailedLogin
 * Increments failed attempt counter; locks account after threshold.
 */
userSchema.methods.recordFailedLogin = async function () {
  this.failedLoginAttempts += 1;
  if (this.failedLoginAttempts >= security.maxLoginAttempts) {
    this.lockoutUntil = new Date(Date.now() + security.lockoutDurationMs);
  }
  await this.save();
};

/**
 * resetLoginAttempts
 * Clears lockout state after a successful login.
 */
userSchema.methods.resetLoginAttempts = async function () {
  this.failedLoginAttempts = 0;
  this.lockoutUntil = null;
  await this.save();
};

/**
 * toSafeObject
 * Returns a plain object with sensitive fields stripped — safe to send in API responses.
 */
userSchema.methods.toSafeObject = function () {
  const obj = this.toObject();
  delete obj.passwordHash;
  delete obj.twoFactorSecret;
  delete obj.twoFactorBackupCodes;
  delete obj.failedLoginAttempts;
  delete obj.lockoutUntil;
  delete obj.passwordResetToken;
  delete obj.passwordResetExpiry;
  delete obj.knownDevices;
  delete obj.ssnLast4;
  delete obj.biometricCredentialId;
  return obj;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
