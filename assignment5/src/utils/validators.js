'use strict';

const { body, param, query } = require('express-validator');

/**
 * passwordRules
 * Enforces strong password policy for a banking app:
 * - 12+ chars, uppercase, lowercase, digit, special char
 *
 * @param {string} field - express-validator field name
 * @returns {ValidationChain}
 */
function passwordRules(field = 'password') {
  return body(field)
    .isLength({ min: 12 })
    .withMessage('Password must be at least 12 characters')
    .matches(/[A-Z]/)
    .withMessage('Password must contain an uppercase letter')
    .matches(/[a-z]/)
    .withMessage('Password must contain a lowercase letter')
    .matches(/\d/)
    .withMessage('Password must contain a digit')
    .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/)
    .withMessage('Password must contain a special character');
}

/**
 * amountRules
 * Validates a monetary amount in cents (integer, positive, within per-transaction limit).
 * Server-side enforcement fixes the "$1,000,000 transfer" vulnerability.
 *
 * @param {string} field
 * @param {number} maxCents
 * @returns {ValidationChain}
 */
function amountRules(field = 'amountCents', maxCents = 500_000) {
  return body(field)
    .isInt({ min: 1, max: maxCents })
    .withMessage(`Amount must be between 1 and ${maxCents} cents`)
    .toInt();
}

/**
 * accountIdRules
 * Validates MongoDB ObjectId for account parameters.
 * Prevents parameter tampering by rejecting non-ObjectId values.
 *
 * @param {string} field
 * @returns {ValidationChain}
 */
function accountIdRules(field = 'accountId') {
  return param(field).isMongoId().withMessage('Invalid account identifier');
}

/**
 * transactionSearchRules
 * Validates query parameters for transaction history searches.
 * Prevents injection via search fields.
 *
 * @returns {ValidationChain[]}
 */
function transactionSearchRules() {
  return [
    query('startDate').optional().isISO8601().withMessage('startDate must be ISO 8601'),
    query('endDate').optional().isISO8601().withMessage('endDate must be ISO 8601'),
    query('type')
      .optional()
      .isIn(['transfer', 'bill_payment', 'deposit', 'withdrawal'])
      .withMessage('Invalid transaction type'),
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  ];
}

/**
 * beneficiaryRules
 * Validates beneficiary creation/update fields.
 *
 * @returns {ValidationChain[]}
 */
function beneficiaryRules() {
  return [
    body('nickname')
      .isLength({ min: 1, max: 50 })
      .matches(/^[\w\s\-'.]+$/)
      .withMessage('Nickname contains invalid characters'),
    body('accountNumber')
      .isLength({ min: 8, max: 17 })
      .isNumeric()
      .withMessage('Account number must be 8-17 digits'),
    body('routingNumber')
      .isLength({ min: 9, max: 9 })
      .isNumeric()
      .withMessage('Routing number must be exactly 9 digits'),
    body('bankName')
      .isLength({ min: 1, max: 100 })
      .matches(/^[\w\s\-'.&]+$/)
      .withMessage('Bank name contains invalid characters'),
  ];
}

module.exports = { passwordRules, amountRules, accountIdRules, transactionSearchRules, beneficiaryRules };
