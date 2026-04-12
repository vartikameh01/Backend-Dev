'use strict';

const crypto = require('crypto');
const { UAParser } = require('ua-parser-js');
const User = require('../models/User');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');

/**
 * buildFingerprint
 * Creates a deterministic fingerprint from IP + User-Agent + Accept-Language.
 * Not cryptographically unique — used as a heuristic signal, not a secret.
 *
 * @param {object} req
 * @returns {string} SHA-256 hex digest (first 16 bytes)
 */
function buildFingerprint(req) {
  const raw = [
    req.ip || '',
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
  ].join('|');
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 32);
}

/**
 * deviceFingerprintMiddleware
 * Attaches req.deviceFingerprint on every authenticated request.
 * Compares against the user's known devices:
 * - If new: logs a "suspicious_device" audit event, adds device to known list.
 * - If known: updates lastSeen.
 *
 * This implements Task 1 — device fingerprinting and suspicious activity detection.
 */
async function deviceFingerprintMiddleware(req, res, next) {
  // Only run for authenticated requests
  if (!req.user) return next();

  const fingerprint = buildFingerprint(req);
  req.deviceFingerprint = fingerprint;

  try {
    const user = await User.findById(req.user.sub).select('+knownDevices').lean();
    if (!user) return next();

    const known = user.knownDevices || [];
    const existingDevice = known.find((d) => d.fingerprint === fingerprint);

    if (!existingDevice) {
      // New device — flag as suspicious and add to the list
      const parser = new UAParser(req.headers['user-agent']);
      const ua = parser.getResult();

      logger.warn('New device detected for user', { userId: req.user.sub, fingerprint, ip: req.ip });

      await auditService.log({
        userId: req.user.sub,
        action: 'suspicious_device',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        deviceFingerprint: fingerprint,
        metadata: {
          browser: ua.browser.name,
          os: ua.os.name,
          isFirstSeen: true,
        },
        severity: 'medium',
      });

      // Add to known devices (cap list at 10)
      const updatedDevices = [
        ...known.slice(-9),
        {
          fingerprint,
          userAgent: req.headers['user-agent'],
          ip: req.ip,
          firstSeen: new Date(),
          lastSeen: new Date(),
        },
      ];
      await User.findByIdAndUpdate(req.user.sub, { $set: { knownDevices: updatedDevices } });
    } else {
      // Known device — just update lastSeen
      await User.findOneAndUpdate(
        { _id: req.user.sub, 'knownDevices.fingerprint': fingerprint },
        { $set: { 'knownDevices.$.lastSeen': new Date() } },
      );
    }
  } catch (err) {
    // Non-fatal — log but don't block the request
    logger.error('Device fingerprint middleware error', { error: err.message });
  }

  next();
}

module.exports = { deviceFingerprintMiddleware, buildFingerprint };
