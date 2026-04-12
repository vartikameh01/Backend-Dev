'use strict';

const nodemailer = require('nodemailer');
const User = require('../models/User');
const { sanitizeForEmail } = require('../utils/sanitizers');
const logger = require('../utils/logger');

/**
 * createTransport
 * Lazy transport creation so tests can run without SMTP configured.
 */
function createTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10) || 587,
    secure: process.env.SMTP_PORT === '465',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

/**
 * sendPasswordResetEmail
 * Sends a password reset email with a time-limited token link.
 * The token is raw (not hashed) — the hash lives in the DB.
 *
 * @param {string} email
 * @param {string} rawToken
 */
async function sendPasswordResetEmail(email, rawToken) {
  const resetUrl = `${process.env.FRONTEND_URL || 'https://quickbank.example.com'}/reset-password?token=${encodeURIComponent(rawToken)}`;

  const html = `
    <p>You requested a password reset for your QuickBank account.</p>
    <p>Click the link below to reset your password. This link expires in 15 minutes.</p>
    <p><a href="${resetUrl}">Reset my password</a></p>
    <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
    <p>For security, never share this link with anyone.</p>
  `;

  await sendEmail({ to: email, subject: 'QuickBank: Password Reset Request', html });
}

/**
 * sendTransactionNotification
 * Sends an email notification after a financial transaction.
 * CRITICAL: description is sanitized before insertion into HTML.
 * Fixes the "unsanitized transaction descriptions allow XSS in emails" vulnerability (Task 2).
 *
 * @param {string} userId
 * @param {object} txInfo - { type, amountCents, description, transactionId }
 */
async function sendTransactionNotification(userId, { type, amountCents, description, transactionId }) {
  try {
    const user = await User.findById(userId).lean();
    if (!user || !user.emailNotifications) return;

    // Sanitize description before embedding in HTML email
    const safeDescription = sanitizeForEmail(description || '');
    const amount = `$${(amountCents / 100).toFixed(2)}`;

    const html = `
      <p>Dear ${sanitizeForEmail(user.firstName)},</p>
      <p>A ${type.replace('_', ' ')} of <strong>${amount}</strong> has been processed on your account.</p>
      ${safeDescription ? `<p>Description: ${safeDescription}</p>` : ''}
      <p>Transaction reference: ${sanitizeForEmail(transactionId)}</p>
      <p>If you did not initiate this transaction, please contact us immediately.</p>
    `;

    await sendEmail({
      to: user.email,
      subject: `QuickBank: ${type.replace('_', ' ')} of ${amount}`,
      html,
    });
  } catch (err) {
    logger.error('Failed to send transaction notification', { error: err.message, userId });
  }
}

/**
 * sendEmail
 * Low-level email sender. All outgoing emails go through here.
 *
 * @param {object} opts - { to, subject, html }
 */
async function sendEmail({ to, subject, html }) {
  try {
    const transport = createTransport();
    await transport.sendMail({
      from: process.env.FROM_EMAIL || 'noreply@quickbank.example.com',
      to,
      subject,
      html,
    });
    logger.info('Email sent', { to, subject });
  } catch (err) {
    logger.error('Failed to send email', { error: err.message, to, subject });
    // Non-fatal — don't re-throw; email failure should not roll back transactions
  }
}

module.exports = { sendPasswordResetEmail, sendTransactionNotification, sendEmail };
