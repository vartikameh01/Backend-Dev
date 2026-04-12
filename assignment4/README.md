# MediBook — Secure Healthcare Appointment System

HIPAA-compliant Node.js/Express API built on MongoDB that addresses every
security vulnerability listed in the "MediBook" scenario.

---

## Quick Start

```bash
cp .env.example .env          # fill in secrets
npm install
npm start                     # production
npm run dev                   # development (nodemon)
npm test                      # run all test suites
npm run test:coverage         # with coverage report
```

---

## Directory Structure

```
assignment4/
├── server.js                   # Application entry point
├── src/
│   ├── config/
│   │   └── database.js         # MongoDB connection (TLS in prod)
│   ├── middleware/
│   │   ├── auth.js             # JWT authentication
│   │   ├── rbac.js             # Role-based access control
│   │   ├── auditLogger.js      # Per-request audit logging
│   │   ├── helmetConfig.js     # Helmet security headers
│   │   ├── rateLimiter.js      # Rate limiting (3 tiers)
│   │   ├── sessionManager.js   # Session + idle timeout
│   │   └── validate.js         # express-validator result handler
│   ├── models/
│   │   ├── User.js             # Patient/Doctor/Nurse/Admin/Insurance
│   │   ├── MedicalRecord.js    # Encrypted PHI fields
│   │   ├── Appointment.js      # Encrypted reason field
│   │   ├── Prescription.js     # Fully encrypted PHI
│   │   └── AuditLog.js         # Immutable, TTL-indexed audit log
│   ├── routes/
│   │   ├── auth.js             # Register, login, refresh, logout, change-password
│   │   ├── patients.js         # Patient CRUD with IDOR protection
│   │   ├── doctors.js          # Doctor search + availability
│   │   ├── appointments.js     # Scheduling CRUD
│   │   ├── medicalRecords.js   # PHI CRUD with role + ownership checks
│   │   └── documents.js        # Secure upload / retrieval / delete
│   ├── services/
│   │   ├── encryptionService.js  # AES-256-GCM + HMAC-SHA256 search hash
│   │   ├── auditService.js       # Structured audit log writer + query
│   │   └── documentService.js   # Magic-byte validation + encrypted storage
│   └── utils/
│       ├── logger.js            # Winston logger (JSON in prod)
│       ├── validators.js        # express-validator chains
│       └── sanitizers.js        # sanitize-html wrappers
└── tests/
    ├── auth.test.js             # Password policy, JWT, session timeouts
    ├── validation.test.js       # Input validation + sanitization
    ├── injection.test.js        # MongoDB injection + XSS prevention
    ├── encryption.test.js       # AES-256-GCM, magic bytes, file limits
    └── rbac.test.js             # RBAC, IDOR, audit ACTIONS
```

---

## Task Implementation Map

### Task 1 — Multi-layered Authentication & Access Control

| Requirement | File | Method / Location |
|---|---|---|
| Strong password enforcement (≥12 chars, uppercase, lowercase, digit, special) | `src/utils/validators.js` | `validatePassword()` |
| Password hashing (bcrypt, 12 rounds) | `src/models/User.js` | `userSchema.pre('save')` |
| Account lockout after 5 failed attempts (30 min) | `src/models/User.js` | `incrementFailedLogin()`, `isAccountLocked()` |
| JWT access + refresh token issuance | `src/middleware/auth.js` | `generateTokens()` |
| JWT verification middleware | `src/middleware/auth.js` | `authenticate()` |
| Role-based access control (Patient/Doctor/Nurse/Admin/Insurance) | `src/middleware/rbac.js` | `requireRole()`, `requireOwnerOrRole()`, `requirePatientSelf()` |
| Patient self-only strict access | `src/middleware/rbac.js` | `requirePatientSelf()` |
| Session idle timeout (15 min patient/admin, 30 min clinical) | `src/middleware/sessionManager.js` | `configureSession()`, inline middleware, `IDLE_TIMEOUT_BY_ROLE` |
| Session creation on login | `src/middleware/sessionManager.js` | `setSessionUser()` |
| Session destruction on logout | `src/middleware/sessionManager.js` | `clearSession()` |
| Session cookie hardening (HttpOnly, Secure, SameSite=strict) | `src/middleware/sessionManager.js` | `configureSession()` — cookie options |
| IDOR fix (URL parameter patient record access) | `src/routes/patients.js` | `GET /:id` — `requireOwnerOrRole()` guard |
| Rate limiting on auth endpoints (5 req/15 min) | `src/middleware/rateLimiter.js` | `authRateLimiter` |

---

### Task 2 — Input Validation & Sanitization

| Requirement | File | Method / Location |
|---|---|---|
| Patient name validation (regex, max 100 chars, unicode-safe) | `src/utils/validators.js` | `validateName()` |
| Email validation (RFC 5322 simplified, max 254 chars) | `src/utils/validators.js` | `validateEmail()` |
| Phone validation (US formats) | `src/utils/validators.js` | `validatePhone()` |
| SSN validation (XXX-XX-XXXX, no 000/666/9xx areas) | `src/utils/validators.js` | `validateSSN()` |
| Date of Birth validation (ISO 8601, past-only, after 1900) | `src/utils/validators.js` | `validateDOB()` |
| Appointment date validation (ISO 8601, future-only, < 2 years) | `src/utils/validators.js` | `validateAppointmentDate()` |
| Insurance member ID validation | `src/utils/validators.js` | `validateInsuranceId()` |
| NPI validation (10 digits) | `src/utils/validators.js` | `validateNPI()` |
| Medical text validation (blocks `<script>`, `<iframe>`, `javascript:`) | `src/utils/validators.js` | `validateMedicalText()` |
| Appointment reason validation | `src/utils/validators.js` | `validateAppointmentReason()` |
| Search query validation (no `${}`) | `src/utils/validators.js` | `validateSearchQuery()` |
| Plain text sanitization (strip all HTML) | `src/utils/sanitizers.js` | `sanitizePlainText()` |
| Medical text sanitization (allow-list tags, strip XSS vectors) | `src/utils/sanitizers.js` | `sanitizeMedicalText()` |
| Doctor notes sanitization | `src/utils/sanitizers.js` | `sanitizeDoctorNotes()` |
| Search query sanitization (strip `${}`) | `src/utils/sanitizers.js` | `sanitizeSearchQuery()` |
| Recursive object sanitization | `src/utils/sanitizers.js` | `sanitizeObject()` |
| validation error handler (422 + field-level details) | `src/middleware/validate.js` | `handleValidationErrors()` |
| All medical record free-text fields sanitized before save | `src/routes/medicalRecords.js` | `POST /` and `PUT /:id` handlers |

---

### Task 3 — Secure Document Upload System

| Requirement | File | Method / Location |
|---|---|---|
| Accept only PDF, JPEG, PNG, DICOM | `src/services/documentService.js` | `ALLOWED_TYPES`, `validateMagicBytes()` |
| Magic-byte validation (never trust client MIME) | `src/services/documentService.js` | `validateMagicBytes()` |
| DICOM detection (128-byte preamble + "DICM") | `src/services/documentService.js` | `validateMagicBytes()` — DICOM branch |
| File size limit (default 10 MB, configurable) | `src/services/documentService.js` | `MAX_FILE_SIZE_BYTES`, `validateAndStoreDocument()` |
| Multer memory storage (no untrusted bytes to disk) | `src/routes/documents.js` | `multer({ storage: memoryStorage() })` |
| Multer file type filter (pre-validation) | `src/routes/documents.js` | `fileFilter` callback |
| Encrypted storage on disk (AES-256-GCM) | `src/services/documentService.js` | `validateAndStoreDocument()` |
| Random UUID filename (no original name on disk) | `src/services/documentService.js` | `validateAndStoreDocument()` — `crypto.randomUUID()` |
| Path traversal prevention (upload) | `src/services/documentService.js` | `path.basename(originalName)` + `safeName` |
| Path traversal prevention (retrieval) | `src/services/documentService.js` | `retrieveDocument()` — basename + `..` check |
| Decrypted retrieval with access logging | `src/routes/documents.js` | `GET /:recordId/:storedName` — `auditService.log` before decrypt |
| IDOR check: document must belong to the requested record | `src/routes/documents.js` | `docEntry` lookup before serving |
| X-Content-Type-Options nosniff on download | `src/routes/documents.js` | response header in GET handler |

---

### Task 4 — MongoDB Injection Protection

| Requirement | File | Method / Location |
|---|---|---|
| Global `express-mongo-sanitize` (strips `$`-prefixed keys) | `server.js` | `app.use(mongoSanitize(...))` with `onSanitize` logger |
| Patient search uses `{ $eq: safeQ }` (no dynamic regex) | `src/routes/patients.js` | `GET /` — `filter.email = { $eq: safeQ }` |
| Doctor specialty search uses `{ $eq: ... }` | `src/routes/doctors.js` | `GET /` — `filter.specialties = { $eq: ... }` |
| Doctor availability uses typed Date objects with `$gte`/`$lte` | `src/routes/doctors.js` | `GET /:id/availability` — `startOfDay`/`endOfDay` Date objects |
| Appointment lookup uses `{ _id: { $eq: req.params.id } }` | `src/routes/appointments.js` | `GET /:id`, `PATCH /:id/cancel` |
| Medical record lookup uses `{ _id: { $eq: ... } }` | `src/routes/medicalRecords.js` | `GET /:id`, `PUT /:id`, `DELETE /:id` |
| Medical record patient query uses `{ patient: { $eq: ... } }` | `src/routes/medicalRecords.js` | `GET /patient/:patientId` |
| Document lookup uses `{ _id: { $eq: ... } }` | `src/routes/documents.js` | All three handlers |
| Search query validation blocks `$` and `{}` characters | `src/utils/validators.js` | `validateSearchQuery()` |
| Search query sanitizer strips `${}` | `src/utils/sanitizers.js` | `sanitizeSearchQuery()` |
| MongoId param validation (`isMongoId()`) on all ID params | `src/utils/validators.js` | `validateMongoId()` — used in all routes |
| Appointment status uses `{ $in: [...] }` with whitelist | `src/routes/doctors.js` | `GET /:id/availability` |

---

### Task 5 — Helmet Security Headers

| Requirement | File | Method / Location |
|---|---|---|
| Content-Security-Policy (strict, no unsafe-inline scripts) | `src/middleware/helmetConfig.js` | `configureHelmet()` — `contentSecurityPolicy.directives` |
| HSTS (2-year max-age, includeSubDomains, preload) | `src/middleware/helmetConfig.js` | `hsts` option |
| X-Frame-Options: DENY (clickjacking protection) | `src/middleware/helmetConfig.js` | `frameguard: { action: 'deny' }` |
| X-Content-Type-Options: nosniff | `src/middleware/helmetConfig.js` | `noSniff: true` |
| Referrer-Policy: no-referrer (prevents PHI in URL leaks) | `src/middleware/helmetConfig.js` | `referrerPolicy: { policy: 'no-referrer' }` |
| X-XSS-Protection | `src/middleware/helmetConfig.js` | `xssFilter: true` |
| X-DNS-Prefetch-Control: off | `src/middleware/helmetConfig.js` | `dnsPrefetchControl: { allow: false }` |
| Cross-Origin-Embedder-Policy | `src/middleware/helmetConfig.js` | `crossOriginEmbedderPolicy: true` |
| Cross-Origin-Opener-Policy: same-origin | `src/middleware/helmetConfig.js` | `crossOriginOpenerPolicy` |
| Cross-Origin-Resource-Policy: same-origin | `src/middleware/helmetConfig.js` | `crossOriginResourcePolicy` |
| Permissions-Policy (camera/mic/geo/payment disabled) | `src/middleware/helmetConfig.js` | manual header middleware after `app.use(helmet(...))` |
| frame-ancestors: 'none' in CSP | `src/middleware/helmetConfig.js` | `frameAncestors: ["'none'"]` in CSP directives |

---

### Task 6 — Encryption at Rest & in Transit

| Requirement | File | Method / Location |
|---|---|---|
| AES-256-GCM encryption (authenticated encryption) | `src/services/encryptionService.js` | `encrypt()`, `decrypt()` |
| Random IV per encryption (prevents IV reuse) | `src/services/encryptionService.js` | `crypto.randomBytes(IV_LENGTH)` in `encrypt()` |
| GCM auth tag integrity check | `src/services/encryptionService.js` | `cipher.getAuthTag()` / `decipher.setAuthTag()` |
| HMAC-SHA256 search hash for encrypted fields | `src/services/encryptionService.js` | `hashForSearch()` |
| User PHI fields encrypted (SSN, DOB, phone, address, insurance) | `src/models/User.js` | `_enc_*` fields + virtual getters/setters |
| SSN hash for equality lookups | `src/models/User.js` | `ssnHash` field + `pre('save')` hook |
| Medical record PHI encrypted (diagnosis, notes, etc.) | `src/models/MedicalRecord.js` | `_enc_*` fields + virtuals |
| Appointment reason encrypted | `src/models/Appointment.js` | `_enc_reason` + virtual |
| Prescription all fields encrypted | `src/models/Prescription.js` | `_enc_*` fields + virtuals |
| Medical documents encrypted on disk | `src/services/documentService.js` | `validateAndStoreDocument()` — `encrypt(buffer.toString('base64'))` |
| TLS enforcement for MongoDB in production | `src/config/database.js` | `tls: NODE_ENV === 'production'` |
| HTTPS enforced via HSTS | `src/middleware/helmetConfig.js` | `hsts` with 2-year max-age |
| Password hashing (bcrypt, 12 rounds) | `src/models/User.js` | `pre('save')` — `bcrypt.hash(password, BCRYPT_ROUNDS)` |
| Sensitive fields excluded from JSON serialisation | `src/models/User.js` | `stripSensitiveFields()` transform |

---

### Task 7 — Comprehensive Security Audit Log

| Requirement | File | Method / Location |
|---|---|---|
| AuditLog schema (action, user, target, IP, user-agent, outcome, timestamp) | `src/models/AuditLog.js` | schema definition |
| Immutable logs (pre-hook blocks update/delete) | `src/models/AuditLog.js` | `pre(['updateOne', ... 'deleteMany'])` |
| TTL auto-expiry (7 years default, configurable) | `src/models/AuditLog.js` | TTL index on `timestamp` |
| Audit ACTIONS constants (all PHI and security events) | `src/services/auditService.js` | `ACTIONS` export |
| `log()` function (persists to DB, falls back to logger on failure) | `src/services/auditService.js` | `log()` |
| `query()` function (compliance reporting with pagination) | `src/services/auditService.js` | `query()` |
| Per-request HTTP audit logging middleware | `src/middleware/auditLogger.js` | `requestAuditLogger()`, `deriveAction()` |
| Login success/failure audit | `src/routes/auth.js` | `POST /login` handler |
| Password change audit | `src/routes/auth.js` | `POST /change-password` handler |
| Patient create/view/update/delete audit | `src/routes/patients.js` | each route handler |
| Medical record create/view/update/delete audit | `src/routes/medicalRecords.js` | each route handler |
| Document upload/view/delete audit | `src/routes/documents.js` | each route handler |
| Appointment create/view/cancel audit | `src/routes/appointments.js` | each route handler |
| Access-denied audit (RBAC rejections) | `src/middleware/rbac.js` | `requireRole()`, `requireOwnerOrRole()` |
| MongoDB injection attempt logging | `server.js` | `mongoSanitize({ onSanitize })` callback |
| Expired/invalid JWT audit | `src/middleware/auth.js` | `authenticate()` catch block |

---

## Security Architecture Overview

### Defense-in-Depth Layers

```
Client Request
    │
    ▼
[1] HSTS + TLS (in transit encryption)
    │
    ▼
[2] Helmet headers (CSP, X-Frame-Options, CORP, COEP, etc.)
    │
    ▼
[3] CORS whitelist
    │
    ▼
[4] Global rate limiter (anti-DoS)
    │
    ▼
[5] express-mongo-sanitize (strips $-operator keys globally)
    │
    ▼
[6] Audit request logger (every request logged)
    │
    ▼
[7] Route-level express-validator (type + format + range checks)
    │
    ▼
[8] handleValidationErrors (abort with 422 on any violation)
    │
    ▼
[9] authenticate (JWT verification)
    │
    ▼
[10] requireRole / requireOwnerOrRole (RBAC + IDOR prevention)
    │
    ▼
[11] sensitiveRateLimiter (additional limit on PHI endpoints)
    │
    ▼
[12] Business logic (sanitize + explicit $eq queries + encrypt PHI)
    │
    ▼
[13] MongoDB (encrypted PHI fields, TLS connection)
    │
    ▼
[14] Audit log write (every PHI access recorded)
```

### IDOR Vulnerability Fix

The original vulnerability allowed accessing other patients' records by changing URL parameters (e.g., `/patients/123` → `/patients/456`).

**Fix:** `requireOwnerOrRole()` in `src/middleware/rbac.js` compares `req.params.id` against `req.user.id`. A patient can only pass the check if the requested ID matches their own authenticated identity. Privileged roles (doctor/admin) may access any record but every access is audit-logged.

### MongoDB Injection Fix

The original search was vulnerable to passing `{ "$gt": "" }` as a search parameter to return all records.

**Fix (layered):**
1. `express-mongo-sanitize` globally strips any key prefixed with `$` from `req.body`, `req.query`, and `req.params`.
2. Validators reject `$` and `{}` characters in query parameters.
3. Sanitizers strip `${}` from any string reaching the query builder.
4. All MongoDB queries use explicit `{ field: { $eq: value } }` — never `{ field: userInput }` directly.
5. Date queries cast to `Date` objects before use — never string comparisons.

### XSS Fix (Doctor Notes)

**Fix:** `sanitizeMedicalText()` in `src/utils/sanitizers.js` uses an allow-list (bold, italic, lists only). All other tags — including `<script>`, `<iframe>`, event handlers, and `javascript:` URIs — are stripped before the content is stored.

---

## HIPAA Compliance Checklist

| HIPAA Safeguard | Implementation |
|---|---|
| §164.312(a)(1) Access Control | RBAC in `rbac.js`; unique user IDs; session timeout |
| §164.312(a)(2)(i) Unique User Identification | `User.email` unique index; JWT `sub` claim |
| §164.312(a)(2)(iii) Automatic Logoff | Idle timeout in `sessionManager.js` |
| §164.312(b) Audit Controls | `AuditLog` model + `auditService.js` + `auditLogger.js` |
| §164.312(c)(1) Integrity | AES-256-GCM auth tag; bcrypt; HMAC search hash |
| §164.312(d) Person Authentication | bcrypt password; account lockout; JWT |
| §164.312(e)(1) Transmission Security | HSTS (2 yr); TLS for MongoDB; HTTPS-only cookies |
| §164.312(e)(2)(ii) Encryption and Decryption | AES-256-GCM on all PHI fields + documents |
| Audit log retention | TTL index: 7 years (2555 days, configurable) |
| Minimum Necessary Standard | Role-specific query scoping; patients see only their own data |

---

## Production Deployment Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Generate a cryptographically random `JWT_SECRET` (≥ 32 chars): `openssl rand -hex 32`
- [ ] Generate a cryptographically random `SESSION_SECRET` (≥ 32 chars)
- [ ] Generate a 32-byte `ENCRYPTION_KEY`: `openssl rand -hex 32`
- [ ] Configure `MONGODB_URI` with TLS enabled and strong credentials
- [ ] Set `ALLOWED_ORIGINS` to your exact frontend domain(s)
- [ ] Configure a reverse proxy (nginx/ALB) to terminate TLS and forward to Node
- [ ] Enable MongoDB encryption-at-rest (WiredTiger AES-256)
- [ ] Restrict `uploads/secure/` directory to process user only (mode 0700)
- [ ] Configure log shipping (CloudWatch / ELK / Splunk) for audit logs
- [ ] Set up alerts on `SECURITY_ACCESS_DENIED` and `SECURITY_INJECTION_ATTEMPT` actions
- [ ] Rotate `ENCRYPTION_KEY` with a key-rotation plan for existing encrypted records
- [ ] Enable MongoDB Atlas backup or equivalent with point-in-time recovery
- [ ] Run `npm audit` and remediate any high/critical advisories before deploying
- [ ] Conduct a penetration test specifically targeting IDOR, injection, and auth flows
- [ ] Review HIPAA Business Associate Agreements with all third-party vendors
- [ ] Document access control policies and train staff on minimum-necessary access

---

## Identified Vulnerabilities & Mitigations

| # | Original Vulnerability | Mitigation |
|---|---|---|
| 1 | IDOR: `/patients/:id` returns any patient's record | `requireOwnerOrRole()` in `rbac.js` |
| 2 | XSS: unescaped HTML in doctor notes | `sanitizeMedicalText()` + `sanitizeDoctorNotes()` in `sanitizers.js` |
| 3 | NoSQL injection: search returns all records | `mongoSanitize` + `$eq` queries + validator/sanitizer chain |
| 4 | Sessions never expire | Idle timeout (15/30 min) + rolling session in `sessionManager.js` |
| 5 | Fake email/phone registrations | `validateEmail()` / `validatePhone()` in `validators.js` |
| 6 | Any string accepted as date → crashes | `isISO8601().toDate()` in `validateDOB()` / `validateAppointmentDate()` |
| 7 | Unvalidated document uploads | Magic-byte check + size limit + MIME filter in `documentService.js` |

---

## Threat Modeling

Each vulnerability is analyzed by attack vector, exploitation method, and potential impact.

### 1. IDOR — Insecure Direct Object Reference
- **Vector:** Authenticated patient changes the `:id` URL parameter to another patient's MongoDB ObjectId.
- **Exploitation:** `GET /patients/507f1f77bcf86cd799439011` → attacker enumerates or guesses IDs to harvest PHI.
- **Impact:** Full exposure of medical history, SSN, insurance details, prescriptions — HIPAA breach, regulatory fines, civil liability.
- **Fix:** `requireOwnerOrRole()` compares `req.params.id` against `req.user.id`; patients are hard-blocked from other IDs at the middleware layer, before any DB query executes.

### 2. XSS — Unescaped HTML in Doctor Notes
- **Vector:** A malicious doctor (or compromised doctor account) saves `<script>alert(document.cookie)</script>` inside a note field.
- **Exploitation:** Any user whose browser renders the note has their session token exfiltrated. In a healthcare portal this could be a patient, nurse, or billing clerk.
- **Impact:** Session hijacking, privilege escalation, unauthorized PHI access or modification on behalf of the victim.
- **Fix:** `sanitizeDoctorNotes()` runs the content through `sanitize-html` with a strict allow-list (bold, italic, lists). All other tags — including `<script>`, event handlers, and `javascript:` URIs — are stripped before storage.

### 3. NoSQL Injection — Doctor/Patient Search
- **Vector:** Attacker sends `{ "name": { "$gt": "" } }` in a query parameter. Unparameterised Mongoose queries treat this as an operator, returning every record.
- **Exploitation:** Full collection dump via a single unauthenticated HTTP request. Combined with IDOR, an attacker can exfiltrate the entire patient database.
- **Impact:** Mass PHI disclosure. Potential for destructive payloads (`$where`, `$regex` with catastrophic backtracking) causing availability loss.
- **Fix (layered):** `express-mongo-sanitize` strips `$`-prefixed keys globally; validators reject `${}` characters; sanitizers scrub them from strings; all queries use `{ field: { $eq: value } }` explicitly.

### 4. Broken Session Management — Sessions Never Expire
- **Vector:** A patient logs in at a hospital kiosk and walks away without logging out. The session remains valid indefinitely.
- **Exploitation:** Any person at the kiosk can resume the session hours or days later with full access to the patient's PHI.
- **Impact:** Unauthorized PHI access, fraudulent appointment creation or cancellation, prescription tampering.
- **Fix:** `IDLE_TIMEOUT_BY_ROLE` enforces 15-minute idle expiry for Patient and Admin; 30 minutes for clinical roles. The session cookie uses `SameSite=Strict` as a secondary CSRF mitigation.

### 5. Weak Input Validation — Fake Registrations
- **Vector:** Attacker submits `email: "not-an-email"`, `phone: "'; DROP TABLE users; --"`, or `dob: "yesterday"` to bypass registration guards.
- **Exploitation:** Pollutes the database with garbage records, evades contact-verification workflows, and may cause downstream crashes when invalid formats are processed.
- **Impact:** Data integrity loss, denial-of-service via crash, potential for follow-on injection if unvalidated strings reach query builders.
- **Fix:** `validateEmail()`, `validatePhone()`, `validateDOB()` use strict regex + `express-validator` type coercion. Any violation returns `422` before the handler runs.

### 6. Type Confusion — Any String Accepted as Date
- **Vector:** `appointmentDate: "next Tuesday"` or `dob: { "$ne": null }` sent in the request body.
- **Exploitation:** Crashes the Node process on `new Date("next Tuesday")` (returns `Invalid Date`), or allows operator injection if the raw string reaches MongoDB.
- **Impact:** Denial-of-service (repeated crash loops), potential injection if combined with vulnerability #3.
- **Fix:** `isISO8601().toDate()` converts and validates the string to a native `Date` object in the validator. Non-ISO strings fail the validation step and never reach the handler.

### 7. Unvalidated File Uploads
- **Vector:** Attacker uploads a PHP webshell named `shell.pdf` with `Content-Type: application/pdf`. The file is saved to disk and served back.
- **Exploitation:** If the server later serves the file through an interpreter (or another service proxies it), arbitrary code executes. Even without execution, a malicious file can exploit vulnerable document viewers.
- **Impact:** Remote code execution, malware distribution to patients/doctors, complete system compromise.
- **Fix:** `validateMagicBytes()` reads the first bytes of the buffer and compares against known signatures (PDF `%PDF`, JPEG `FFD8FF`, PNG `89504E47`, DICOM `DICM` at offset 128). Files failing the signature check are rejected regardless of declared MIME type.

### 8. CSRF — Cross-Site Request Forgery
- **Vector:** An attacker hosts a malicious webpage that silently submits a form to `POST /appointments` while the victim has an active session.
- **Exploitation:** The victim's browser automatically includes the session cookie, causing the request to execute under their identity.
- **Impact:** Unauthorized appointment creation/cancellation, prescription modification, profile data changes.
- **Fix:** Session cookies are set with `SameSite=Strict`, which causes browsers to withhold the cookie on all cross-site requests (form submissions, fetch calls, image loads). This is the recommended modern CSRF defence for APIs that serve a same-origin frontend. State-changing endpoints additionally require a valid `Authorization: Bearer` JWT header, which cross-site requests cannot obtain.

---

## Testing Documentation

| Test File | What It Covers |
|---|---|
| `tests/auth.test.js` | Password policy enforcement, bcrypt hashing, JWT issuance and verification, account lockout after 5 failures, session idle timeout, role-based route access |
| `tests/validation.test.js` | All `validators.js` chains (email, phone, SSN, DOB, appointment date, NPI, medical text, search query); sanitizer output for XSS payloads; 422 responses on invalid input |
| `tests/injection.test.js` | NoSQL injection attempts (`$gt`, `$ne`, `$where`) in search/query params; XSS payloads in doctor notes, appointment reasons, and patient names; `express-mongo-sanitize` integration |
| `tests/encryption.test.js` | AES-256-GCM round-trip; IV uniqueness across multiple encryptions; magic-byte rejection for non-PDF/JPEG/PNG/DICOM files; file size limit enforcement |
| `tests/rbac.test.js` | IDOR prevention (patient A cannot access patient B's record); role-specific access (Nurse cannot delete records; Insurance cannot view prescriptions); audit log entries on access-denied events |

---

## Security Code Review Checklist

Use this checklist when reviewing any new route, model, or service added to MediBook.

### Authentication & Sessions
- [ ] Route uses `authenticate` middleware before any handler logic
- [ ] Role restriction applied with `requireRole()` or `requireOwnerOrRole()`
- [ ] Patient-owned resources use `requirePatientSelf()` or `requireOwnerOrRole()`
- [ ] New session variables set through `setSessionUser()`, not `req.session` directly
- [ ] No long-lived credentials stored in cookies without rotation

### Input Validation
- [ ] All route parameters validated with `validateMongoId()` (or equivalent)
- [ ] All free-text fields validated with `validateMedicalText()` or appropriate chain
- [ ] All date fields use `isISO8601().toDate()` coercion
- [ ] `handleValidationErrors` called immediately after each validation chain
- [ ] Search parameters validated with `validateSearchQuery()` (blocks `${}`)

### Sanitization
- [ ] Plain-text storage fields pass through `sanitizePlainText()`
- [ ] Rich-text / clinical fields pass through `sanitizeMedicalText()` or `sanitizeDoctorNotes()`
- [ ] Search terms pass through `sanitizeSearchQuery()` before any DB query
- [ ] No raw `req.body` properties used directly in MongoDB queries

### MongoDB Query Safety
- [ ] All queries use `{ field: { $eq: value } }` form — never `{ field: userInput }`
- [ ] Date range queries use typed `Date` objects with `$gte`/`$lte`, never raw strings
- [ ] Aggregation pipelines do not interpolate user input into `$where` or `$function`
- [ ] All route params that become query values are validated as `isMongoId()`

### PHI & Encryption
- [ ] New PHI fields on models use `_enc_*` naming convention with virtual getter/setter
- [ ] `encryptionService.encrypt()` called in `pre('save')` hook, not in the route handler
- [ ] Fields used in equality searches have a corresponding `_hash` field (HMAC-SHA256)
- [ ] `stripSensitiveFields()` transform confirmed to exclude new sensitive fields from JSON output

### Audit Logging
- [ ] Every handler that reads, creates, updates, or deletes PHI calls `auditService.log()`
- [ ] `ACTIONS` constant used (no magic strings) and new action added to the constant if needed
- [ ] Access-denied paths call `auditService.log()` with `outcome: 'failure'`
- [ ] Document retrieval handler logs before decryption, not after

### File Uploads
- [ ] `multer` uses `memoryStorage()` — no files written to disk before validation
- [ ] `documentService.validateAndStoreDocument()` called; raw `req.file.buffer` never saved directly
- [ ] Stored filename is `crypto.randomUUID()` — no user-controlled path component
- [ ] Download handler performs `..` path traversal check before constructing file path
