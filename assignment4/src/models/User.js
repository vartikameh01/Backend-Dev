'use strict';

/**
 * User.js
 * Unified model for all MediBook users: Patient, Doctor, Nurse, Admin, Insurance.
 * Task 1: Role-based access control via the `role` field.
 * Task 6: Sensitive PHI fields stored encrypted (SSN, dateOfBirth, phone, address).
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { encrypt, decrypt, hashForSearch } = require('../services/encryptionService');

const ROLES = ['patient', 'doctor', 'nurse', 'admin', 'insurance'];
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;

// ─── Schema ───────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },
    // HMAC hash of SSN for equality-based lookups without plaintext storage
    ssnHash: { type: String, index: true },

    password: { type: String, required: true, select: false },

    role: {
      type: String,
      enum: ROLES,
      required: true,
      default: 'patient',
    },

    // Encrypted PHI fields — stored as opaque strings in MongoDB
    _enc_firstName:   { type: String },
    _enc_lastName:    { type: String },
    _enc_dateOfBirth: { type: String },
    _enc_phone:       { type: String },
    _enc_ssn:         { type: String },
    _enc_address:     { type: String },

    // Insurance (encrypted)
    _enc_insuranceMemberId:  { type: String },
    _enc_insuranceProvider:  { type: String },
    _enc_insurancePolicyNum: { type: String },

    // Doctor-specific (not encrypted — not PHI)
    npi:         { type: String },
    specialties: [{ type: String }],
    licenseNumber: { type: String },

    // Account management
    isActive:          { type: Boolean, default: true },
    failedLoginCount:  { type: Number, default: 0 },
    lockedUntil:       { type: Date },
    lastLogin:         { type: Date },
    passwordChangedAt: { type: Date },
    mustChangePassword: { type: Boolean, default: false },
  },
  {
    timestamps: true,
    toJSON:   { virtuals: true, transform: stripSensitiveFields },
    toObject: { virtuals: true },
  }
);

// ─── Virtual decryptors ───────────────────────────────────────────────────────
function makeEncryptedVirtual(name) {
  userSchema.virtual(name)
    .get(function () {
      if (!this[`_enc_${name}`]) return undefined;
      try { return decrypt(this[`_enc_${name}`]); } catch { return undefined; }
    })
    .set(function (val) {
      this[`_enc_${name}`] = val ? encrypt(val) : undefined;
    });
}

[
  'firstName', 'lastName', 'dateOfBirth', 'phone', 'ssn',
  'address', 'insuranceMemberId', 'insuranceProvider', 'insurancePolicyNum',
].forEach(makeEncryptedVirtual);

// ─── Pre-save hooks ───────────────────────────────────────────────────────────
userSchema.pre('save', async function (next) {
  // Hash password if modified
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, BCRYPT_ROUNDS);
    this.passwordChangedAt = new Date();
  }
  // Keep SSN search hash in sync
  if (this.isModified('_enc_ssn') && this._enc_ssn) {
    const plain = decrypt(this._enc_ssn);
    this.ssnHash = hashForSearch(plain);
  }
  next();
});

// ─── Instance methods ─────────────────────────────────────────────────────────
userSchema.methods.verifyPassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

userSchema.methods.isAccountLocked = function () {
  if (this.lockedUntil && this.lockedUntil > new Date()) return true;
  return false;
};

userSchema.methods.incrementFailedLogin = async function () {
  this.failedLoginCount += 1;
  if (this.failedLoginCount >= 5) {
    this.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // lock 30 min
  }
  await this.save();
};

userSchema.methods.resetFailedLogin = async function () {
  this.failedLoginCount = 0;
  this.lockedUntil = undefined;
  this.lastLogin = new Date();
  await this.save();
};

// ─── Serialisation: never expose password or raw encrypted blobs ──────────────
function stripSensitiveFields(doc, ret) {
  delete ret.password;
  delete ret.__v;
  // Remove raw encrypted storage keys from the serialised output
  Object.keys(ret).forEach((k) => { if (k.startsWith('_enc_')) delete ret[k]; });
  return ret;
}

const User = mongoose.model('User', userSchema);
module.exports = { User, ROLES };
