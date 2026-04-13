

const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const logger = require('../utils/logger');

// Allowed MIME types and their extensions
const ALLOWED_FILE_TYPES = {
  // Documents
  'application/pdf': ['.pdf'],
  'application/msword': ['.doc'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
  'application/vnd.ms-powerpoint': ['.ppt'],
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
  // Images
  'image/jpeg': ['.jpg', '.jpeg'],
  'image/png': ['.png'],
  'image/gif': ['.gif'],
  'image/webp': ['.webp'],
  // Videos
  'video/mp4': ['.mp4'],
  'video/webm': ['.webm'],
  'video/quicktime': ['.mov']
};

// Magic bytes for file type verification
const MAGIC_BYTES = {
  'application/pdf': [Buffer.from([0x25, 0x50, 0x44, 0x46])],  // %PDF
  'image/jpeg': [Buffer.from([0xFF, 0xD8, 0xFF])],
  'image/png': [Buffer.from([0x89, 0x50, 0x4E, 0x47])],
  'image/gif': [Buffer.from([0x47, 0x49, 0x46])],                // GIF
  'video/mp4': [Buffer.from([0x00, 0x00, 0x00]), Buffer.from([0x66, 0x74, 0x79, 0x70])],
};


const verifyMagicBytes = (buffer, mimeType) => {
  const signatures = MAGIC_BYTES[mimeType];
  if (!signatures) return true; // Skip check if no known signature

  return signatures.some(sig =>
    buffer.slice(0, sig.length).equals(sig)
  );
};


const scanForMaliciousContent = (buffer) => {
  const content = buffer.toString('utf8', 0, Math.min(buffer.length, 65536));

  const suspiciousPatterns = [
    /<script[\s>]/i,
    /javascript:/i,
    /vbscript:/i,
    /on\w+\s*=/i,                  // Event handlers
    /eval\s*\(/i,
    /exec\s*\(/i,
    /system\s*\(/i,
    /cmd\.exe/i,
    /\/bin\/sh/i,
    /powershell/i,
    /<%[\s\S]*?%>/,                 // ASP/JSP tags
    /<\?php/i,                      // PHP tags
    /MZ[\x00-\xFF]{2}/,            // PE executable header
    /\x7fELF/                       // ELF executable header
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(content)) {
      return { safe: false, reason: `Suspicious pattern detected: ${pattern.source}` };
    }
  }

  return { safe: true };
};

// Storage configuration with secure filenames
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate random filename to prevent path traversal and overwriting
    const uniqueSuffix = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uniqueSuffix}${ext}`);
  }
});

// File filter
const fileFilter = (req, file, cb) => {
  // Check MIME type
  if (!ALLOWED_FILE_TYPES[file.mimetype]) {
    logger.warn('Rejected file upload: invalid MIME type', {
      mimetype: file.mimetype,
      originalname: file.originalname,
      ip: req.ip,
      userId: req.session?.userId
    });
    return cb(new Error('File type not allowed. Allowed types: PDF, DOC, DOCX, PPT, PPTX, JPG, PNG, GIF, WEBP, MP4, WEBM, MOV'), false);
  }

  // Check extension matches MIME type
  const ext = path.extname(file.originalname).toLowerCase();
  if (!ALLOWED_FILE_TYPES[file.mimetype].includes(ext)) {
    logger.warn('Rejected file upload: extension/MIME mismatch', {
      mimetype: file.mimetype,
      extension: ext,
      originalname: file.originalname,
      ip: req.ip
    });
    return cb(new Error('File extension does not match its content type.'), false);
  }

  cb(null, true);
};

// Document upload (PDFs, docs, presentations)
const documentUpload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 50 * 1024 * 1024, // 50MB
    files: 5
  }
});

// Video upload (larger size limit)
const videoUpload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_VIDEO_SIZE) || 500 * 1024 * 1024, // 500MB
    files: 1
  }
});

// Image upload (profile pics, course thumbnails)
const imageUpload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const imageTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!imageTypes.includes(file.mimetype)) {
      return cb(new Error('Only image files (JPG, PNG, GIF, WEBP) are allowed.'), false);
    }
    cb(null, true);
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB for images
    files: 1
  }
});

/**
 * Post-upload validation middleware
 * Verifies magic bytes and scans for malicious content
 */
const postUploadValidation = async (req, res, next) => {
  if (!req.file && !req.files) return next();

  const files = req.files || [req.file];

  for (const file of files) {
    try {
      const buffer = fs.readFileSync(file.path);

      // Verify magic bytes
      if (!verifyMagicBytes(buffer, file.mimetype)) {
        fs.unlinkSync(file.path);
        logger.warn('File upload rejected: magic bytes mismatch', {
          originalname: file.originalname,
          claimedType: file.mimetype,
          userId: req.session?.userId
        });
        return res.status(400).json({
          error: 'File content does not match its type. The file may be corrupted or disguised.'
        });
      }

      // Scan for malicious content
      const scanResult = scanForMaliciousContent(buffer);
      if (!scanResult.safe) {
        fs.unlinkSync(file.path);
        logger.warn('Malicious file upload blocked', {
          originalname: file.originalname,
          reason: scanResult.reason,
          userId: req.session?.userId,
          ip: req.ip
        });
        return res.status(400).json({
          error: 'File contains suspicious content and has been rejected.'
        });
      }

      logger.info('File upload validated', {
        filename: file.filename,
        originalname: file.originalname,
        size: file.size,
        mimetype: file.mimetype,
        userId: req.session?.userId
      });
    } catch (error) {
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return next(error);
    }
  }

  next();
};

module.exports = {
  documentUpload,
  videoUpload,
  imageUpload,
  postUploadValidation,
  verifyMagicBytes,
  scanForMaliciousContent
};
