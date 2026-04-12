'use strict';

const { createLogger, format, transports } = require('winston');
const { combine, timestamp, json, errors, colorize, simple } = format;

/**
 * Centralized Winston logger.
 * In production: JSON to stdout + optional MongoDB transport.
 * In development: human-readable colorized console output.
 */
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    errors({ stack: true }),
    timestamp(),
    json()
  ),
  defaultMeta: { service: 'medibook' },
  transports: [
    new transports.Console({
      format: process.env.NODE_ENV === 'production'
        ? combine(timestamp(), json())
        : combine(colorize(), simple()),
      silent: process.env.NODE_ENV === 'test',
    }),
  ],
});

module.exports = logger;
