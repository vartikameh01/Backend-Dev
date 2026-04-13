
const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

const Course = require('../models/Course');
const { isAuthenticated, authorize, isMfaVerified } = require('../middleware/auth');
const { documentUpload, videoUpload, imageUpload, postUploadValidation } = require('../middleware/fileUpload');
const { uploadLimiter } = require('../middleware/rateLimiter');
const { validateMongoId } = require('../utils/sanitizer');
const { validationResult } = require('express-validator');
const logger = require('../utils/logger');


router.post('/document/:courseId',
  isAuthenticated,
  isMfaVerified,
  authorize('instructor', 'admin'),
  uploadLimiter,
  validateMongoId,
  documentUpload.single('file'),
  postUploadValidation,
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });

      const course = await Course.findById(req.params.courseId).select('instructor');
      if (!course) return res.status(404).json({ error: 'Course not found.' });
      if (course.instructor.toString() !== req.session.userId && req.session.role !== 'admin') {
        fs.unlinkSync(req.file.path);
        return res.status(403).json({ error: 'Not authorized.' });
      }

      const material = {
        title: req.body.title || req.file.originalname,
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size
      };

      await Course.findByIdAndUpdate(req.params.courseId, { $push: { materials: material } });

      logger.audit('FILE_UPLOADED', {
        courseId: req.params.courseId,
        filename: req.file.filename,
        originalname: req.file.originalname,
        userId: req.session.userId
      });

      res.status(201).json({ message: 'File uploaded successfully.', material });
    } catch (err) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      next(err);
    }
  }
);

router.post('/video/:courseId',
  isAuthenticated,
  isMfaVerified,
  authorize('instructor', 'admin'),
  uploadLimiter,
  validateMongoId,
  videoUpload.single('video'),
  postUploadValidation,
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      if (!req.file) return res.status(400).json({ error: 'No video uploaded.' });

      const course = await Course.findById(req.params.courseId).select('instructor');
      if (!course) {
        fs.unlinkSync(req.file.path);
        return res.status(404).json({ error: 'Course not found.' });
      }
      if (course.instructor.toString() !== req.session.userId && req.session.role !== 'admin') {
        fs.unlinkSync(req.file.path);
        return res.status(403).json({ error: 'Not authorized.' });
      }

      const video = {
        title: req.body.title || req.file.originalname,
        url: `/uploads/${req.file.filename}`,
        order: parseInt(req.body.order) || 0
      };

      await Course.findByIdAndUpdate(req.params.courseId, { $push: { videos: video } });

      logger.audit('VIDEO_UPLOADED', {
        courseId: req.params.courseId,
        filename: req.file.filename,
        userId: req.session.userId
      });

      res.status(201).json({ message: 'Video uploaded successfully.', video });
    } catch (err) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      next(err);
    }
  }
);

router.get('/:filename', isAuthenticated, (req, res, next) => {
  // Prevent path traversal
  const filename = path.basename(req.params.filename);
  const filePath = path.join(__dirname, '../../uploads', filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found.' });
  }

  logger.audit('FILE_ACCESSED', {
    filename,
    userId: req.session.userId,
    ip: req.ip
  });

  res.sendFile(filePath);
});

module.exports = router;
