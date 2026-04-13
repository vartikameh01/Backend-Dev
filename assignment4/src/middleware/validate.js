'use strict';

/**
 * validate.js
 * Express-validator result handler.
 * Call after express-validator chains to abort with 422 on any validation error.
 */

const { validationResult } = require('express-validator');

/**
 * handleValidationErrors
 * Middleware that checks express-validator results and returns 422 if invalid.
 * Never exposes raw DB errors or stack traces.
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: 'Validation failed',
      details: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }
  return next();
}

module.exports = { handleValidationErrors };
