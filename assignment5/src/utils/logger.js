'use strict';

const { createLogger, format, transports } = require('winston');

const { combine, timestamp, json, errors, printf, colorize } = format;

const devFormat = combine(
  colorize(),
  timestamp(),
  printf(({ level, message, timestamp: ts, ...meta }) => {
    const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    return `${ts} [${level}]: ${message}${metaStr}`;
  }),
);

const prodFormat = combine(timestamp(), errors({ stack: true }), json());

/**
 * logger
 * Winston logger instance.
 * - In production: JSON to stdout (structured, machine-parseable)
 * - In development: colorized console output
 * Used by: all middleware and services for structured logging.
 */
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: process.env.NODE_ENV === 'production' ? prodFormat : devFormat,
  transports: [new transports.Console()],
  exceptionHandlers: [new transports.Console()],
  rejectionHandlers: [new transports.Console()],
});

module.exports = logger;
