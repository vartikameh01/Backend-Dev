'use strict';

const Transaction = require('../models/Transaction');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

/**
 * fraudDetectionService
 * Implements real-time fraud detection indicators (Task 5).
 *
 * Rules (configurable thresholds):
 * 1. Velocity check: > 5 transfers in 60 seconds from the same user
 * 2. High-value from new device: large transfer from a device never seen before
 * 3. Rapid amount escalation: transactions increasing >10x within 5 minutes
 * 4. After-hours large transfer: amount > $3,000 outside business hours (9–17 UTC)
 */

const VELOCITY_WINDOW_MS = 60 * 1000;
const VELOCITY_MAX_COUNT = 5;
const HIGH_VALUE_THRESHOLD_CENTS = 300_000; // $3,000

/**
 * evaluateTransfer
 * Runs fraud heuristics before a transfer is committed.
 * Returns { blocked: boolean, reason: string }
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {number} params.amountCents
 * @param {string} params.fromAccountId
 * @param {string} params.toAccountId
 * @param {string} params.deviceFingerprint
 * @param {string} params.ipAddress
 */
async function evaluateTransfer({ userId, amountCents, fromAccountId, toAccountId, deviceFingerprint, ipAddress }) {
  try {
    // ── Rule 1: Velocity ──
    const since = new Date(Date.now() - VELOCITY_WINDOW_MS);
    const recentCount = await Transaction.countDocuments({
      initiatedBy: userId,
      type: 'transfer',
      createdAt: { $gte: since },
    });

    if (recentCount >= VELOCITY_MAX_COUNT) {
      logger.warn('Fraud: velocity limit triggered', { userId, recentCount });
      return { blocked: true, reason: 'velocity_exceeded' };
    }

    // ── Rule 2: High-value + unknown device ──
    if (amountCents >= HIGH_VALUE_THRESHOLD_CENTS && deviceFingerprint) {
      const knownDeviceActivity = await AuditLog.findOne({
        userId,
        deviceFingerprint,
        action: { $in: ['login_success', 'transfer_completed'] },
        createdAt: { $lt: new Date(Date.now() - 5 * 60 * 1000) }, // device must be > 5 min old
      }).lean();

      if (!knownDeviceActivity) {
        logger.warn('Fraud: high-value transfer from new/unestablished device', { userId, amountCents });
        return { blocked: true, reason: 'high_value_unknown_device' };
      }
    }

    // ── Rule 3: Rapid escalation ──
    const escalationWindow = new Date(Date.now() - 5 * 60 * 1000);
    const recentTxns = await Transaction.find({
      initiatedBy: userId,
      type: 'transfer',
      createdAt: { $gte: escalationWindow },
    })
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    if (recentTxns.length > 0) {
      const minPrevious = Math.min(...recentTxns.map((t) => t.amountCents));
      if (amountCents > minPrevious * 10) {
        logger.warn('Fraud: rapid amount escalation', { userId, amountCents, minPrevious });
        return { blocked: true, reason: 'rapid_escalation' };
      }
    }

    // ── Rule 4: After-hours large transfer ──
    const hour = new Date().getUTCHours();
    const isAfterHours = hour < 9 || hour >= 17;
    if (isAfterHours && amountCents >= HIGH_VALUE_THRESHOLD_CENTS) {
      // Don't block — flag for review instead
      logger.info('Fraud indicator: after-hours large transfer (not blocked)', { userId, amountCents, hour, ipAddress });
    }

    return { blocked: false, reason: null };
  } catch (err) {
    // Fraud detection failure should not block legitimate transactions — log and allow
    logger.error('Fraud detection error (allowing transaction)', { error: err.message });
    return { blocked: false, reason: null };
  }
}

module.exports = { evaluateTransfer };
