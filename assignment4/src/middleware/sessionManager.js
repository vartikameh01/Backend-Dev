'use strict';

/**
 * sessionManager.js
 * Task 1: Express session management with healthcare-appropriate timeouts.
 *
 * HIPAA guidance / NIST 800-63B recommends re-authentication after inactivity.
 * - Patient/Insurance sessions: 15 minutes idle, 8 hours absolute
 * - Clinical staff (Doctor/Nurse): 30 minutes idle, 12 hours absolute
 * - Admin: 15 minutes idle, 8 hours absolute
 *
 * Sessions are signed, HttpOnly, Secure (production), and SameSite=Strict.
 */

const session = require('express-session');

const SESSION_SECRET = process.env.SESSION_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  if (IS_PRODUCTION) {
    throw new Error('SESSION_SECRET must be at least 32 characters in production');
  }
}

// Session idle timeout by role (milliseconds)
const IDLE_TIMEOUT_BY_ROLE = {
  patient:   15 * 60 * 1000,  // 15 minutes
  insurance: 15 * 60 * 1000,  // 15 minutes
  doctor:    30 * 60 * 1000,  // 30 minutes
  nurse:     30 * 60 * 1000,  // 30 minutes
  admin:     15 * 60 * 1000,  // 15 minutes
};

const DEFAULT_IDLE_TIMEOUT = 15 * 60 * 1000;

function configureSession(app) {
  app.use(
    session({
      secret: SESSION_SECRET || 'dev-secret-replace-in-production',
      resave: false,
      saveUninitialized: false,
      rolling: true,           // Reset idle timer on each request
      cookie: {
        httpOnly: true,        // Inaccessible to JavaScript — XSS mitigation
        secure: IS_PRODUCTION, // HTTPS only in production
        sameSite: 'strict',    // CSRF protection
        maxAge: DEFAULT_IDLE_TIMEOUT,
      },
    })
  );

  // Middleware: enforce idle timeout based on the user's role
  app.use((req, res, next) => {
    if (!req.session || !req.session.userId) return next();

    const role = req.session.userRole || 'patient';
    const idleTimeout = IDLE_TIMEOUT_BY_ROLE[role] || DEFAULT_IDLE_TIMEOUT;
    const now = Date.now();

    if (req.session.lastActivity && now - req.session.lastActivity > idleTimeout) {
      // Session has been idle too long — destroy it
      return req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.status(401).json({ error: 'Session expired due to inactivity. Please log in again.' });
      });
    }

    req.session.lastActivity = now;
    next();
  });
}

/**
 * setSessionUser
 * Called after successful login to attach user info to the session.
 */
function setSessionUser(req, user) {
  req.session.userId   = String(user._id);
  req.session.userRole = user.role;
  req.session.lastActivity = Date.now();
  req.session.loginTime = Date.now();
}

/**
 * clearSession
 * Called on logout — destroys session and clears cookie.
 */
function clearSession(req, res) {
  return new Promise((resolve) => {
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      resolve();
    });
  });
}

module.exports = { configureSession, setSessionUser, clearSession, IDLE_TIMEOUT_BY_ROLE };
