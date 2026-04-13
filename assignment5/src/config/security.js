'use strict';

/**
 * Central security configuration constants.
 * All monetary values are in USD cents to avoid floating-point issues.
 */
const security = {
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,

  maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10) || 5,
  lockoutDurationMs: (parseInt(process.env.LOCKOUT_DURATION_MINUTES, 10) || 30) * 60 * 1000,

  passwordResetTokenTTLMs:
    (parseInt(process.env.PASSWORD_RESET_TOKEN_TTL_MINUTES, 10) || 15) * 60 * 1000,

  // Transaction limits (cents)
  singleTxLimitCents: parseInt(process.env.SINGLE_TX_LIMIT_CENTS, 10) || 500_000,  // $5,000
  dailyTxLimitCents: parseInt(process.env.DAILY_TX_LIMIT_CENTS, 10) || 1_000_000, // $10,000

  // Transactions above this threshold require 2FA confirmation (cents)
  tx2faThresholdCents: parseInt(process.env.TX_2FA_THRESHOLD_CENTS, 10) || 100_000, // $1,000

  sessionMaxAgeMs: 15 * 60 * 1000, // 15 minutes idle timeout

  jwtExpiry: process.env.JWT_EXPIRY || '15m',
  jwtRefreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',

  totpIssuer: process.env.TOTP_ISSUER || 'QuickBank',
  totpWindow: 1, // allow ±1 step for clock skew
};

module.exports = security;
