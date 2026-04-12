# EduLearn Disaster Recovery Plan

## 1. Overview
This document outlines the disaster recovery (DR) procedures for the EduLearn platform, including backup schedules, session management, and restoration procedures.

---

## 2. Backup Strategy

### 2.1 Automated Database Backups
- **Tool**: `mongodump` with `--gzip` compression
- **Schedule**: Daily at 02:00 UTC (configurable via `BACKUP_CRON` env var)
- **Retention**: 30 days (configurable via `BACKUP_RETENTION_DAYS`)
- **Location**: `/backups/` directory (configure offsite storage for production)
- **Integrity**: SHA-256 checksum stored in `.meta.json` alongside each backup

### 2.2 Session Resilience
- **Storage**: Sessions stored in MongoDB via `connect-mongo` (not in-memory)
- **Behavior**: Sessions survive server restarts and horizontal scaling
- **Expiry**: Sessions auto-expire via MongoDB TTL index
- **Encryption**: Session data encrypted at rest using `ENCRYPTION_KEY`

### 2.3 Offsite Backup (Production)
```bash
# Example: Sync backups to AWS S3
aws s3 sync ./backups s3://edulearn-backups/$(date +%Y-%m) --delete
```

---

## 3. Recovery Procedures

### 3.1 Database Recovery
```bash
# List available backups
node -e "const b = require('./src/services/backup'); b.listBackups().then(console.log)"

# Restore a specific backup (CAUTION: drops existing collections)
node -e "require('./src/services/backup').restoreBackup('edulearn-backup-2024-01-01T02-00-00-000Z')"
```

### 3.2 Session Recovery
- Sessions are persistent in MongoDB — no action needed after server restart
- If session store is corrupted, users will need to re-authenticate
- Admin can clear all sessions: `db.sessions.deleteMany({})`

### 3.3 Server Restart Checklist
1. Verify MongoDB is running and accessible
2. Check `.env` file for all required variables
3. Run `npm start` — sessions and data are restored automatically
4. Verify health endpoint: `GET /health`

---

## 4. Incident Response

### 4.1 Security Breach
1. Immediately rotate `SESSION_SECRET` and `ENCRYPTION_KEY`
2. Run `db.sessions.deleteMany({})` to invalidate all active sessions
3. Force all users to reset passwords
4. Review `logs/security.log` for attack vectors
5. Restore from last clean backup if data was tampered

### 4.2 Data Corruption
1. Stop the application server
2. Verify last backup integrity (checksum in `.meta.json`)
3. Restore from verified backup using `restoreBackup()`
4. Restart application and verify functionality

### 4.3 Account Compromise
1. Lock compromised accounts: `User.findByIdAndUpdate(id, { isActive: false })`
2. Invalidate sessions: `db.sessions.deleteMany({ 'session.userId': userId })`
3. Review audit logs for unauthorized actions
4. Reset password and notify user via secure channel

---

## 5. Monitoring & Alerting

### 5.1 Key Metrics to Monitor
- Failed login attempts (threshold: >10/minute per IP)
- Unusual file upload patterns
- Session creation rate
- Database connection pool exhaustion
- Error rate spikes

### 5.2 Log Files
| File | Purpose |
|------|---------|
| `logs/combined.log` | All application events |
| `logs/error.log` | Errors only |
| `logs/security.log` | Security events (warn+) |

### 5.3 Health Check
```bash
curl http://localhost:3000/health
# Expected: {"status":"healthy","timestamp":"...","uptime":...}
```

---

## 6. Production Deployment Checklist

- [ ] `NODE_ENV=production` set
- [ ] `SESSION_SECRET` is a 64+ char random string
- [ ] `ENCRYPTION_KEY` is a 32-byte random key
- [ ] MongoDB Atlas with IP allowlisting configured
- [ ] HTTPS enforced (Nginx/ALB with SSL certificate)
- [ ] Rate limiting tested under load
- [ ] Automated backup cron job running
- [ ] Offsite backup sync configured (S3/GCS)
- [ ] Log aggregation configured (CloudWatch/Datadog)
- [ ] Alerts configured for security events
- [ ] MFA enforced for all instructor accounts
- [ ] File upload directory not web-accessible directly
- [ ] `uploads/.gitkeep` committed, actual files in `.gitignore`
