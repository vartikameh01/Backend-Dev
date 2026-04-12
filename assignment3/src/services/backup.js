/**
 * Disaster Recovery & Backup Service - EduLearn
 * Database backups and session management for resilience
 */

const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const logger = require('../utils/logger');

const BACKUP_DIR = process.env.BACKUP_PATH || path.join(__dirname, '../../backups');
const RETENTION_DAYS = parseInt(process.env.BACKUP_RETENTION_DAYS) || 30;

/**
 * Ensure backup directory exists
 */
const ensureBackupDir = () => {
  if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
  }
};

/**
 * Create a MongoDB backup using mongodump
 */
const createBackup = () => {
  return new Promise((resolve, reject) => {
    ensureBackupDir();

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupName = `edulearn-backup-${timestamp}`;
    const backupPath = path.join(BACKUP_DIR, backupName);
    const mongoUri = process.env.MONGODB_URI;

    // Use mongodump for backup
    const cmd = `mongodump --uri="${mongoUri}" --out="${backupPath}" --gzip`;

    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        logger.error('Backup failed', { error: error.message, stderr });
        return reject(error);
      }

      // Calculate checksum for integrity verification
      const checksum = calculateDirectoryChecksum(backupPath);

      const metadata = {
        timestamp: new Date().toISOString(),
        backupName,
        checksum,
        mongoUri: mongoUri.replace(/\/\/.*@/, '//<credentials>@') // Redact credentials
      };

      fs.writeFileSync(
        path.join(BACKUP_DIR, `${backupName}.meta.json`),
        JSON.stringify(metadata, null, 2)
      );

      logger.info('Backup created successfully', { backupName, checksum });
      resolve({ backupName, checksum, path: backupPath });
    });
  });
};

/**
 * Restore from a backup
 */
const restoreBackup = (backupName) => {
  return new Promise((resolve, reject) => {
    const backupPath = path.join(BACKUP_DIR, backupName);
    const metaPath = path.join(BACKUP_DIR, `${backupName}.meta.json`);

    if (!fs.existsSync(backupPath)) {
      return reject(new Error('Backup not found'));
    }

    // Verify checksum before restore
    if (fs.existsSync(metaPath)) {
      const metadata = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
      const currentChecksum = calculateDirectoryChecksum(backupPath);

      if (currentChecksum !== metadata.checksum) {
        logger.error('Backup integrity check failed!', { backupName });
        return reject(new Error('Backup integrity check failed. Checksum mismatch.'));
      }
    }

    const mongoUri = process.env.MONGODB_URI;
    const cmd = `mongorestore --uri="${mongoUri}" --gzip --drop "${backupPath}"`;

    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        logger.error('Restore failed', { error: error.message });
        return reject(error);
      }

      logger.info('Restore completed', { backupName });
      resolve({ message: 'Restore successful', backupName });
    });
  });
};

/**
 * Remove backups older than retention period
 */
const cleanOldBackups = () => {
  ensureBackupDir();

  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - RETENTION_DAYS);

  const files = fs.readdirSync(BACKUP_DIR);
  let removed = 0;

  for (const file of files) {
    const filePath = path.join(BACKUP_DIR, file);
    const stat = fs.statSync(filePath);

    if (stat.mtime < cutoffDate) {
      fs.rmSync(filePath, { recursive: true, force: true });
      removed++;
    }
  }

  logger.info('Old backups cleaned', { removed, cutoffDate: cutoffDate.toISOString() });
  return { removed };
};

/**
 * List available backups
 */
const listBackups = () => {
  ensureBackupDir();

  return fs.readdirSync(BACKUP_DIR)
    .filter(f => f.endsWith('.meta.json'))
    .map(f => {
      const meta = JSON.parse(fs.readFileSync(path.join(BACKUP_DIR, f), 'utf8'));
      return meta;
    })
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
};

/**
 * Calculate checksum of directory contents for integrity checking
 */
const calculateDirectoryChecksum = (dirPath) => {
  const hash = crypto.createHash('sha256');

  const processDir = (dir) => {
    if (!fs.existsSync(dir)) return;
    const items = fs.readdirSync(dir).sort();

    for (const item of items) {
      const itemPath = path.join(dir, item);
      const stat = fs.statSync(itemPath);

      if (stat.isDirectory()) {
        processDir(itemPath);
      } else {
        const content = fs.readFileSync(itemPath);
        hash.update(content);
      }
    }
  };

  processDir(dirPath);
  return hash.digest('hex');
};

/**
 * Session health check - verify MongoStore connection
 */
const checkSessionStore = async (sessionStore) => {
  return new Promise((resolve) => {
    sessionStore.length((err, len) => {
      if (err) {
        logger.error('Session store health check failed', { error: err.message });
        resolve({ healthy: false, error: err.message });
      } else {
        resolve({ healthy: true, activeSessions: len });
      }
    });
  });
};

module.exports = {
  createBackup,
  restoreBackup,
  cleanOldBackups,
  listBackups,
  checkSessionStore
};
