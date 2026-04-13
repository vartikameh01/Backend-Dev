/**
 * Course Routes - EduLearn
 */

const express = require('express');
const router = express.Router();
const { validationResult } = require('express-validator');

const Course = require('../models/Course');
const User = require('../models/User');
const { isAuthenticated, authorize, isOwnerOrAdmin, isMfaVerified } = require('../middleware/auth');
const { validateCourseInput, validateMongoId } = require('../utils/sanitizer');
const logger = require('../utils/logger');

// ========================
// GET /api/courses
// Public - list published courses
// ========================
router.get('/', async (req, res, next) => {
  try {
    // Only allow safe sort fields to prevent injection
    const allowedSortFields = ['createdAt', 'price', 'title', 'rating.average'];
    const sortField = allowedSortFields.includes(req.query.sort) ? req.query.sort : 'createdAt';
    const sortOrder = req.query.order === 'asc' ? 1 : -1;

    // Sanitize category filter
    const validCategories = ['programming', 'design', 'business', 'science', 'math', 'language', 'other'];
    const filter = { isPublished: true };
    if (req.query.category && validCategories.includes(req.query.category)) {
      filter.category = req.query.category;
    }

    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const skip = (page - 1) * limit;

    const [courses, total] = await Promise.all([
      Course.find(filter)
        .select('-videos -materials -quizzes -enrolledStudents')
        .populate('instructor', 'name')
        .sort({ [sortField]: sortOrder })
        .skip(skip)
        .limit(limit)
        .lean(),
      Course.countDocuments(filter)
    ]);

    res.json({ courses, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    next(err);
  }
});

// ========================
// POST /api/courses
// Instructor only
// ========================
router.post('/', isAuthenticated, isMfaVerified, authorize('instructor', 'admin'), validateCourseInput, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { title, description, category, price } = req.body;
    const course = new Course({
      title,
      description,
      category,
      price: price || 0,
      isPremium: (price || 0) > 0,
      instructor: req.session.userId
    });

    await course.save();
    await User.findByIdAndUpdate(req.session.userId, { $push: { createdCourses: course._id } });

    logger.audit('COURSE_CREATED', { courseId: course._id, instructorId: req.session.userId });
    res.status(201).json({ message: 'Course created', course });
  } catch (err) {
    next(err);
  }
});

// ========================
// GET /api/courses/:id
// ========================
router.get('/:id', validateMongoId, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const course = await Course.findById(req.params.id)
      .populate('instructor', 'name bio')
      .populate('quizzes', 'title timeLimit');

    if (!course) return res.status(404).json({ error: 'Course not found.' });
    if (!course.isPublished) return res.status(404).json({ error: 'Course not found.' });

    res.json({ course });
  } catch (err) {
    next(err);
  }
});

// ========================
// PUT /api/courses/:id
// Instructor (owner) or admin only
// ========================
router.put('/:id',
  isAuthenticated,
  isMfaVerified,
  authorize('instructor', 'admin'),
  validateMongoId,
  validateCourseInput,
  isOwnerOrAdmin(async (req) => {
    const course = await Course.findById(req.params.id).select('instructor');
    return course?.instructor?.toString();
  }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { title, description, category, price } = req.body;
      const course = await Course.findByIdAndUpdate(
        req.params.id,
        { title, description, category, price: price || 0, isPremium: (price || 0) > 0 },
        { new: true, runValidators: true }
      );

      if (!course) return res.status(404).json({ error: 'Course not found.' });

      logger.audit('COURSE_UPDATED', { courseId: course._id, userId: req.session.userId });
      res.json({ message: 'Course updated', course });
    } catch (err) {
      next(err);
    }
  }
);

// ========================
// DELETE /api/courses/:id
// ========================
router.delete('/:id',
  isAuthenticated,
  authorize('instructor', 'admin'),
  validateMongoId,
  isOwnerOrAdmin(async (req) => {
    const course = await Course.findById(req.params.id).select('instructor');
    return course?.instructor?.toString();
  }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      await Course.findByIdAndDelete(req.params.id);
      logger.audit('COURSE_DELETED', { courseId: req.params.id, userId: req.session.userId });
      res.json({ message: 'Course deleted.' });
    } catch (err) {
      next(err);
    }
  }
);

// ========================
// POST /api/courses/:id/enroll
// Student only
// ========================
router.post('/:id/enroll', isAuthenticated, authorize('student'), validateMongoId, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const course = await Course.findById(req.params.id);
    if (!course || !course.isPublished) return res.status(404).json({ error: 'Course not found.' });

    const alreadyEnrolled = course.enrolledStudents.includes(req.session.userId);
    if (alreadyEnrolled) return res.status(409).json({ error: 'Already enrolled in this course.' });

    await Promise.all([
      Course.findByIdAndUpdate(req.params.id, { $addToSet: { enrolledStudents: req.session.userId } }),
      User.findByIdAndUpdate(req.session.userId, { $addToSet: { enrolledCourses: req.params.id } })
    ]);

    logger.audit('COURSE_ENROLLED', { courseId: req.params.id, userId: req.session.userId });
    res.json({ message: 'Enrolled successfully.' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
