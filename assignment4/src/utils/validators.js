'use strict';

/**
 * validators.js
 * Task 2: Comprehensive input validation rules for all MediBook entities.
 * Used by express-validator in route handlers.
 */

const { body, param, query } = require('express-validator');

// ─── Regex Patterns ───────────────────────────────────────────────────────────
// SSN: XXX-XX-XXXX (no all-zeros segments, no 000/666/900-999 area)
const SSN_REGEX = /^(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}$/;

// US phone: (XXX) XXX-XXXX or XXX-XXX-XXXX or 10 digits
const PHONE_REGEX = /^(\+1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}$/;

// Email: RFC 5322 simplified — the standard HTML5 pattern
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// Name: letters, spaces, hyphens, apostrophes (international-safe)
const NAME_REGEX = /^[\p{L}\s'\-]{1,100}$/u;

// NPI (National Provider Identifier): exactly 10 digits
const NPI_REGEX = /^\d{10}$/;

// Insurance member ID: alphanumeric, 6-20 chars
const INSURANCE_ID_REGEX = /^[A-Z0-9]{6,20}$/i;

// ─── Reusable field validators ────────────────────────────────────────────────

const validateName = (field) =>
  body(field)
    .trim()
    .notEmpty().withMessage(`${field} is required`)
    .matches(NAME_REGEX).withMessage(`${field} contains invalid characters`)
    .isLength({ max: 100 }).withMessage(`${field} must be at most 100 characters`);

const validateEmail = (field = 'email') =>
  body(field)
    .trim()
    .toLowerCase()
    .notEmpty().withMessage('Email is required')
    .matches(EMAIL_REGEX).withMessage('Invalid email address')
    .isLength({ max: 254 }).withMessage('Email too long');

const validatePhone = (field = 'phone') =>
  body(field)
    .optional()
    .trim()
    .matches(PHONE_REGEX).withMessage('Invalid phone number format');

const validateSSN = () =>
  body('ssn')
    .optional()
    .trim()
    .matches(SSN_REGEX).withMessage('Invalid SSN format (expected XXX-XX-XXXX)');

const validateDOB = () =>
  body('dateOfBirth')
    .notEmpty().withMessage('Date of birth is required')
    .isISO8601().withMessage('Date of birth must be a valid ISO 8601 date (YYYY-MM-DD)')
    .toDate()
    .custom((val) => {
      const now = new Date();
      const minDate = new Date('1900-01-01');
      if (val > now) throw new Error('Date of birth cannot be in the future');
      if (val < minDate) throw new Error('Date of birth is implausibly early');
      return true;
    });

const validateAppointmentDate = () =>
  body('appointmentDate')
    .notEmpty().withMessage('Appointment date is required')
    .isISO8601().withMessage('Appointment date must be a valid ISO 8601 datetime')
    .toDate()
    .custom((val) => {
      const now = new Date();
      const maxFuture = new Date();
      maxFuture.setFullYear(maxFuture.getFullYear() + 2);
      if (val < now) throw new Error('Appointment date must be in the future');
      if (val > maxFuture) throw new Error('Appointment date is too far in the future');
      return true;
    });

const validatePassword = () =>
  body('password')
    .isLength({ min: 12, max: 128 }).withMessage('Password must be 12–128 characters')
    .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
    .matches(/\d/).withMessage('Password must contain a digit')
    .matches(/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/)
    .withMessage('Password must contain a special character');

const validateMongoId = (field) =>
  param(field)
    .isMongoId().withMessage(`${field} must be a valid identifier`);

const validateInsuranceId = () =>
  body('insuranceMemberId')
    .optional()
    .trim()
    .matches(INSURANCE_ID_REGEX).withMessage('Invalid insurance member ID');

const validateNPI = () =>
  body('npi')
    .optional()
    .trim()
    .matches(NPI_REGEX).withMessage('NPI must be exactly 10 digits');

// Free-text medical fields: allow medical terminology characters, block HTML tags
const validateMedicalText = (field, maxLen = 5000) =>
  body(field)
    .optional()
    .trim()
    .isLength({ max: maxLen })
    .withMessage(`${field} must be at most ${maxLen} characters`)
    // Block raw HTML tags — sanitizer will handle encoding, but reject clear injection
    .not().matches(/<script|<iframe|javascript:/i)
    .withMessage(`${field} contains forbidden content`);

const validateAppointmentReason = () =>
  body('reason')
    .trim()
    .notEmpty().withMessage('Appointment reason is required')
    .isLength({ max: 500 }).withMessage('Reason must be at most 500 characters')
    .not().matches(/<script|<iframe|javascript:/i)
    .withMessage('Reason contains forbidden content');

// Search query param — no operators, length-limited
const validateSearchQuery = () =>
  query('q')
    .optional()
    .trim()
    .isLength({ max: 100 }).withMessage('Search query too long')
    .not().matches(/[{}$]/).withMessage('Invalid characters in search query');

module.exports = {
  validateName,
  validateEmail,
  validatePhone,
  validateSSN,
  validateDOB,
  validateAppointmentDate,
  validatePassword,
  validateMongoId,
  validateInsuranceId,
  validateNPI,
  validateMedicalText,
  validateAppointmentReason,
  validateSearchQuery,
  SSN_REGEX,
  PHONE_REGEX,
  EMAIL_REGEX,
  NPI_REGEX,
};
