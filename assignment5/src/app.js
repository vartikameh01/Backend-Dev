'use strict';

const express = require('express');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const helmetConfig = require('./middleware/helmetConfig');
const { generalApiLimiter } = require('./middleware/rateLimiter');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const { deviceFingerprintMiddleware } = require('./middleware/deviceFingerprint');

const authRoutes = require('./routes/auth');
const accountRoutes = require('./routes/accounts');
const transactionRoutes = require('./routes/transactions');
const beneficiaryRoutes = require('./routes/beneficiaries');
const loanRoutes = require('./routes/loans');
const profileRoutes = require('./routes/profile');

const app = express();

// ─── Trust proxy (required for req.ip behind load balancer / nginx) ───────────
app.set('trust proxy', 1);

// ─── Security headers (Task 4) ────────────────────────────────────────────────
app.use(...helmetConfig());

// ─── Request parsing ──────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));       // Prevent large payload DoS
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(compression());

// ─── MongoDB injection prevention (Task 2) ────────────────────────────────────
// Sanitizes req.body, req.params, req.query — removes $ and . from keys
app.use(mongoSanitize({ replaceWith: '_' }));

// ─── HTTPS enforcement (Task 4) ───────────────────────────────────────────────
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(301, `https://${req.hostname}${req.url}`);
  }
  next();
});

// ─── Session with encrypted MongoStore (Task 4) ───────────────────────────────
if (process.env.NODE_ENV !== 'test') {
  app.use(
    session({
      secret: process.env.SESSION_SECRET || 'dev-only-change-in-production',
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        crypto: { secret: process.env.SESSION_SECRET || 'dev-only-change-in-production' },
        ttl: 15 * 60, // 15-minute idle session timeout
      }),
      cookie: {
        httpOnly: true,        // XSS protection — JS cannot read cookie
        secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
        sameSite: 'strict',    // CSRF protection
        maxAge: 15 * 60 * 1000,
      },
      name: '__Host-qb.sid', // __Host- prefix enforces Secure + no Domain + Path=/
    }),
  );
}

// ─── General rate limiting (Task 9) ──────────────────────────────────────────
app.use('/api', generalApiLimiter);

// ─── Device fingerprinting (Task 1 — requires auth) ──────────────────────────
// Runs after auth middleware on protected routes; harmless on public routes
app.use(deviceFingerprintMiddleware);

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/accounts', accountRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/beneficiaries', beneficiaryRoutes);
app.use('/api/loans', loanRoutes);
app.use('/api/profile', profileRoutes);

// ─── Health check (no auth — used by load balancer) ──────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ─── Error handlers ───────────────────────────────────────────────────────────
app.use(notFound);
app.use(errorHandler);

module.exports = app;
