'use strict';

const { validationResult } = require('express-validator');

/**
 * handleValidation
 * Collects express-validator errors and returns a 422 with field-level messages.
 * Must be placed after validation chains in the route handler array.
 * Never leaks internal details — only returns validated field names and messages.
 *
 * Usage:
 *   router.post('/transfer', [amountRules(), accountIdRules()], handleValidation, controller)
 */
function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: 'Validation failed',
      details: errors.array().map(({ path, msg }) => ({ field: path, message: msg })),
    });
  }
  next();
}

module.exports = { handleValidation };
