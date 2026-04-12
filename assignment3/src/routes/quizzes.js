/**
 * Quiz Routes - EduLearn
 * Server-side grading prevents answer manipulation
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { validationResult } = require('express-validator');

const Quiz = require('../models/Quiz');
const Course = require('../models/Course');
const { isAuthenticated, authorize, isOwnerOrAdmin, isMfaVerified } = require('../middleware/auth');
const { validateQuizInput, validateMongoId } = require('../utils/sanitizer');
const { quizSubmitLimiter } = require('../middleware/rateLimiter');
const logger = require('../utils/logger');

// ========================
// POST /api/quizzes
// Instructor creates quiz
// ========================
router.post('/', isAuthenticated, isMfaVerified, authorize('instructor', 'admin'), validateQuizInput, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { title, courseId, questions, timeLimit, maxAttempts } = req.body;

    const course = await Course.findById(courseId).select('instructor');
    if (!course) return res.status(404).json({ error: 'Course not found.' });
    if (course.instructor.toString() !== req.session.userId && req.session.role !== 'admin') {
      return res.status(403).json({ error: 'You can only add quizzes to your own courses.' });
    }

    const quiz = new Quiz({
      title,
      course: courseId,
      instructor: req.session.userId,
      questions,
      timeLimit: timeLimit || 30,
      maxAttempts: maxAttempts || 3
    });

    await quiz.save();
    await Course.findByIdAndUpdate(courseId, { $push: { quizzes: quiz._id } });

    logger.audit('QUIZ_CREATED', { quizId: quiz._id, courseId, instructorId: req.session.userId });
    res.status(201).json({ message: 'Quiz created', quizId: quiz._id });
  } catch (err) {
    next(err);
  }
});

// ========================
// GET /api/quizzes/:id
// Returns questions WITHOUT correct answers
// ========================
router.get('/:id', isAuthenticated, validateMongoId, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const quiz = await Quiz.findById(req.params.id).select('-submissions -questions.correctAnswer');
    if (!quiz || !quiz.isPublished) return res.status(404).json({ error: 'Quiz not found.' });

    res.json({ quiz });
  } catch (err) {
    next(err);
  }
});

// ========================
// POST /api/quizzes/:id/submit
// Server-side grading - prevents answer manipulation
// ========================
router.post('/:id/submit', isAuthenticated, authorize('student'), quizSubmitLimiter, validateMongoId, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { answers } = req.body;
    const userId = req.session.userId;

    // Validate answers format
    if (!Array.isArray(answers)) {
      return res.status(400).json({ error: 'Answers must be an array.' });
    }

    // Fetch quiz WITH correct answers (server-side only)
    const quiz = await Quiz.findById(req.params.id);
    if (!quiz || !quiz.isPublished) return res.status(404).json({ error: 'Quiz not found.' });

    // Check attempt limit
    const userSubmissions = quiz.submissions.filter(s => s.student.toString() === userId);
    if (userSubmissions.length >= quiz.maxAttempts) {
      return res.status(429).json({ error: `Maximum ${quiz.maxAttempts} attempt(s) allowed.` });
    }

    // Server-side grading (never trust client scores)
    let score = 0;
    let maxScore = 0;
    const gradedAnswers = [];

    for (let i = 0; i < quiz.questions.length; i++) {
      const question = quiz.questions[i];
      maxScore += question.points;

      const submitted = answers.find(a => a.questionIndex === i);
      const selectedOption = submitted ? parseInt(submitted.selectedOption) : -1;

      // Validate selectedOption is within range
      const isValid = selectedOption >= 0 && selectedOption < question.options.length;
      const isCorrect = isValid && selectedOption === question.correctAnswer;

      if (isCorrect) score += question.points;
      gradedAnswers.push({ questionIndex: i, selectedOption: isValid ? selectedOption : -1 });
    }

    const percentage = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;

    // Create tamper-proof hash of submission
    const answerHash = crypto
      .createHash('sha256')
      .update(JSON.stringify({ userId, quizId: req.params.id, gradedAnswers, score, submittedAt: new Date().toISOString() }))
      .digest('hex');

    quiz.submissions.push({
      student: userId,
      answers: gradedAnswers,
      score,
      maxScore,
      percentage,
      answerHash
    });

    await quiz.save();

    logger.audit('QUIZ_SUBMITTED', {
      quizId: req.params.id,
      userId,
      score,
      maxScore,
      percentage,
      attemptNumber: userSubmissions.length + 1
    });

    res.json({ message: 'Quiz submitted', score, maxScore, percentage });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
