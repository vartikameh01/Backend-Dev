'use strict';

/**
 * rbac.test.js
 * Tests for: Role-Based Access Control (Task 1) and IDOR prevention.
 * Uses a mock req/res/next pattern — no DB connection needed.
 */

process.env.JWT_SECRET     = 'test-secret-minimum-32-characters-xx';
process.env.SESSION_SECRET = 'test-session-secret-minimum-32-chars';
process.env.ENCRYPTION_KEY = 'a'.repeat(64);
process.env.NODE_ENV = 'test';

const { requireRole, requireOwnerOrRole, requirePatientSelf } = require('../src/middleware/rbac');
const { ACTIONS } = require('../src/services/auditService');

// ─── Mock helpers ─────────────────────────────────────────────────────────────
function mockReq({ userId = '111', role = 'patient', params = {} } = {}) {
  return {
    user: { id: userId, role },
    params,
    path: '/test',
    method: 'GET',
    ip: '127.0.0.1',
    headers: { 'user-agent': 'jest' },
  };
}

function mockRes() {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json   = jest.fn().mockReturnValue(res);
  return res;
}

// ─── requireRole ──────────────────────────────────────────────────────────────
describe('requireRole (Task 1 — RBAC)', () => {
  test('allows request when role matches', async () => {
    const next = jest.fn();
    const req  = mockReq({ role: 'doctor' });
    const res  = mockRes();
    await requireRole('doctor', 'admin')(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  test('allows admin through any role gate', async () => {
    const next = jest.fn();
    const req  = mockReq({ role: 'admin' });
    const res  = mockRes();
    await requireRole('doctor', 'admin')(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('blocks patient from doctor-only endpoint', async () => {
    const next = jest.fn();
    const req  = mockReq({ role: 'patient' });
    const res  = mockRes();
    await requireRole('doctor', 'admin')(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('blocks insurance from PHI write endpoint', async () => {
    const next = jest.fn();
    const req  = mockReq({ role: 'insurance' });
    const res  = mockRes();
    await requireRole('doctor', 'nurse', 'admin')(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('returns 401 when req.user is absent', async () => {
    const next = jest.fn();
    const req  = { params: {}, path: '/test', method: 'GET', ip: '127.0.0.1', headers: {} };
    const res  = mockRes();
    await requireRole('admin')(req, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
  });
});

// ─── requireOwnerOrRole (IDOR prevention) ─────────────────────────────────────
describe('requireOwnerOrRole (Task 1 — IDOR prevention)', () => {
  test('allows patient to access their own resource', async () => {
    const next = jest.fn();
    const req  = mockReq({ userId: 'abc123', role: 'patient', params: { id: 'abc123' } });
    const res  = mockRes();
    await requireOwnerOrRole('admin')(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('blocks patient from accessing another patient\'s resource', async () => {
    const next = jest.fn();
    const req  = mockReq({ userId: 'abc123', role: 'patient', params: { id: 'xyz789' } });
    const res  = mockRes();
    await requireOwnerOrRole('admin')(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('allows admin to access any resource (IDOR bypass via role)', async () => {
    const next = jest.fn();
    const req  = mockReq({ userId: 'admin1', role: 'admin', params: { id: 'patient-xyz' } });
    const res  = mockRes();
    await requireOwnerOrRole('admin')(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('blocks doctor from accessing arbitrary patient (not in role list)', async () => {
    const next = jest.fn();
    const req  = mockReq({ userId: 'doc1', role: 'doctor', params: { id: 'patient1' } });
    const res  = mockRes();
    // Only admin allowed via role
    await requireOwnerOrRole('admin')(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('allows doctor through when doctor is in role list', async () => {
    const next = jest.fn();
    const req  = mockReq({ userId: 'doc1', role: 'doctor', params: { patientId: 'patient1' } });
    const res  = mockRes();
    await requireOwnerOrRole('doctor', 'admin')(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('uses patientId param when id is absent', async () => {
    const next = jest.fn();
    const req  = mockReq({ userId: 'p1', role: 'patient', params: { patientId: 'p1' } });
    const res  = mockRes();
    await requireOwnerOrRole('admin')(req, res, next);
    expect(next).toHaveBeenCalled();
  });
});

// ─── requirePatientSelf ───────────────────────────────────────────────────────
describe('requirePatientSelf (Task 1 — strict self-access)', () => {
  test('allows patient to access their own resource', () => {
    const next = jest.fn();
    const req  = mockReq({ userId: 'self123', role: 'patient', params: { id: 'self123' } });
    const res  = mockRes();
    requirePatientSelf(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  test('blocks patient from accessing another patient', () => {
    const next = jest.fn();
    const req  = mockReq({ userId: 'self123', role: 'patient', params: { id: 'other456' } });
    const res  = mockRes();
    requirePatientSelf(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('blocks unauthenticated request', () => {
    const next = jest.fn();
    const req  = { params: { id: 'p1' }, path: '/test', method: 'GET', ip: '127.0.0.1', headers: {} };
    const res  = mockRes();
    requirePatientSelf(req, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
  });
});

// ─── ACTIONS constant completeness check ──────────────────────────────────────
describe('Audit ACTIONS (Task 7)', () => {
  test('all PHI-related actions are defined', () => {
    expect(ACTIONS.PATIENT_VIEW).toBeDefined();
    expect(ACTIONS.RECORD_VIEW).toBeDefined();
    expect(ACTIONS.DOCUMENT_UPLOAD).toBeDefined();
    expect(ACTIONS.PRESCRIPTION_CREATE).toBeDefined();
    expect(ACTIONS.ACCESS_DENIED).toBeDefined();
    expect(ACTIONS.INJECTION_ATTEMPT).toBeDefined();
  });
});
