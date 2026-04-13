'use strict';

/**
 * auditLogger.js
 * Task 7: Express middleware that logs every HTTP request to the audit system.
 * Skips health checks and static assets to avoid noise.
 * Captures: method, path, status, user, IP, user-agent, response time.
 */

const { log, ACTIONS } = require('../services/auditService');

const SKIP_PATHS = new Set(['/health', '/favicon.ico']);

/**
 * requestAuditLogger
 * Attached globally in server.js — fires on every request.
 */
function requestAuditLogger(req, res, next) {
  if (SKIP_PATHS.has(req.path)) return next();

  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    const action = deriveAction(req);

    log({
      action,
      userId:    req.user?.id || req.session?.userId || null,
      userRole:  req.user?.role || req.session?.userRole || null,
      ip:        req.ip,
      userAgent: req.headers['user-agent'] || '',
      outcome:   res.statusCode < 400 ? 'success' : 'failure',
      metadata:  {
        method:       req.method,
        path:         req.path,
        statusCode:   res.statusCode,
        durationMs:   duration,
        // Never log request body — could contain PHI
      },
    });
  });

  next();
}

/**
 * deriveAction
 * Map the HTTP method + path prefix to an audit action constant.
 */
function deriveAction(req) {
  const method = req.method;
  const path   = req.path.toLowerCase();

  if (path.startsWith('/api/auth')) {
    if (path.includes('login'))  return method === 'POST' ? ACTIONS.LOGIN_SUCCESS : ACTIONS.ACCESS_DENIED;
    if (path.includes('logout')) return ACTIONS.LOGOUT;
    return ACTIONS.TOKEN_REFRESH;
  }
  if (path.startsWith('/api/medical-records')) {
    if (method === 'GET')    return ACTIONS.RECORD_VIEW;
    if (method === 'POST')   return ACTIONS.RECORD_CREATE;
    if (method === 'PUT' || method === 'PATCH') return ACTIONS.RECORD_UPDATE;
    if (method === 'DELETE') return ACTIONS.RECORD_DELETE;
  }
  if (path.startsWith('/api/documents')) {
    if (method === 'POST') return ACTIONS.DOCUMENT_UPLOAD;
    if (method === 'GET')  return ACTIONS.DOCUMENT_VIEW;
    if (method === 'DELETE') return ACTIONS.DOCUMENT_DELETE;
  }
  if (path.startsWith('/api/patients')) {
    if (method === 'GET')    return ACTIONS.PATIENT_VIEW;
    if (method === 'POST')   return ACTIONS.PATIENT_CREATE;
    if (method === 'PUT' || method === 'PATCH') return ACTIONS.PATIENT_UPDATE;
    if (method === 'DELETE') return ACTIONS.PATIENT_DELETE;
  }
  if (path.startsWith('/api/appointments')) {
    return ACTIONS.APPOINTMENT_VIEW;
  }
  return `HTTP_${method}`;
}

module.exports = { requestAuditLogger };
