'use strict';

require('dotenv').config();
const express = require('express');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');

const { configureHelmet } = require('./src/middleware/helmetConfig');
const { globalRateLimiter } = require('./src/middleware/rateLimiter');
const { configureSession } = require('./src/middleware/sessionManager');
const { requestAuditLogger } = require('./src/middleware/auditLogger');
const { connectDatabase } = require('./src/config/database');
const logger = require('./src/utils/logger');

const authRoutes = require('./src/routes/auth');
const patientRoutes = require('./src/routes/patients');
const doctorRoutes = require('./src/routes/doctors');
const appointmentRoutes = require('./src/routes/appointments');
const medicalRecordRoutes = require('./src/routes/medicalRecords');
const documentRoutes = require('./src/routes/documents');

const app = express();

// ─── Security Middleware ──────────────────────────────────────────────────────
configureHelmet(app);           // Task 5: Helmet with healthcare-specific config
configureSession(app);          // Task 1: Session management with timeouts
app.use(compression());

// ─── Body Parsing ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '50kb' }));        // Limit payload size
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

// ─── MongoDB Injection Protection ────────────────────────────────────────────
// Task 4: Strip $-prefixed keys from all incoming requests
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    logger.warn('MongoDB injection attempt blocked', {
      ip: req.ip,
      path: req.path,
      key,
    });
  },
}));

// ─── CORS ─────────────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',');
app.use(require('cors')({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ─── Global Rate Limiting ─────────────────────────────────────────────────────
// Task 1: Protect all endpoints
app.use(globalRateLimiter);

// ─── Audit Logging ────────────────────────────────────────────────────────────
// Task 7: Log every incoming request
app.use(requestAuditLogger);

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/patients', patientRoutes);
app.use('/api/doctors', doctorRoutes);
app.use('/api/appointments', appointmentRoutes);
app.use('/api/medical-records', medicalRecordRoutes);
app.use('/api/documents', documentRoutes);

// ─── Health check (unauthenticated, no PHI) ───────────────────────────────────
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ─── Global Error Handler ─────────────────────────────────────────────────────
// Never leak stack traces or internal details to clients
app.use((err, req, res, _next) => {
  const status = err.status || 500;
  logger.error('Unhandled error', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    ip: req.ip,
  });
  res.status(status).json({
    error: status < 500 ? err.message : 'Internal server error',
  });
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

async function start() {
  await connectDatabase();
  app.listen(PORT, () => {
    logger.info(`MediBook server running on port ${PORT} [${process.env.NODE_ENV}]`);
  });
}

if (require.main === module) {
  start().catch((err) => {
    logger.error('Startup failure', { message: err.message });
    process.exit(1);
  });
}

module.exports = app; // exported for tests
