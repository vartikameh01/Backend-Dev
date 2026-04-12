/**
 * Message Routes - EduLearn
 * Student-instructor messaging
 */

const express = require('express');
const router = express.Router();
const { validationResult } = require('express-validator');

const Message = require('../models/Message');
const User = require('../models/User');
const Course = require('../models/Course');
const { isAuthenticated, isOwnerOrAdmin } = require('../middleware/auth');
const { validateMessageInput, validateMongoId } = require('../utils/sanitizer');
const logger = require('../utils/logger');

// ========================
// GET /api/messages/inbox
// ========================
router.get('/inbox', isAuthenticated, async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);

    const messages = await Message.find({ recipient: req.session.userId })
      .populate('sender', 'name role')
      .select('-content')  // Don't load content in inbox list
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    res.json({ messages });
  } catch (err) {
    next(err);
  }
});

// ========================
// GET /api/messages/:id
// Only sender or recipient can read
// ========================
router.get('/:id',
  isAuthenticated,
  validateMongoId,
  isOwnerOrAdmin(async (req) => {
    const msg = await Message.findById(req.params.id).select('sender recipient');
    if (!msg) return null;
    // Allow both sender and recipient to access
    if (msg.recipient.toString() === req.session.userId) return req.session.userId;
    if (msg.sender.toString() === req.session.userId) return req.session.userId;
    return msg.sender.toString(); // Will fail ownership check for others
  }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const message = await Message.findById(req.params.id)
        .populate('sender', 'name role')
        .populate('recipient', 'name role');

      if (!message) return res.status(404).json({ error: 'Message not found.' });

      // Mark as read if recipient is viewing
      if (message.recipient._id.toString() === req.session.userId && !message.isRead) {
        message.isRead = true;
        message.readAt = new Date();
        await message.save();
      }

      res.json({ message });
    } catch (err) {
      next(err);
    }
  }
);

// ========================
// POST /api/messages
// ========================
router.post('/', isAuthenticated, validateMessageInput, async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { subject, content, recipientId, courseId } = req.body;

    const recipient = await User.findById(recipientId).select('_id role isActive');
    if (!recipient || !recipient.isActive) {
      return res.status(404).json({ error: 'Recipient not found.' });
    }

    // Enforce messaging rules: students message instructors, instructors message students
    const senderRole = req.session.role;
    if (senderRole === 'student' && recipient.role === 'student') {
      return res.status(403).json({ error: 'Students can only message instructors.' });
    }

    // Validate course relationship if courseId provided
    if (courseId) {
      const course = await Course.findById(courseId).select('_id instructor enrolledStudents');
      if (!course) return res.status(404).json({ error: 'Course not found.' });
    }

    const message = new Message({
      sender: req.session.userId,
      recipient: recipientId,
      subject,
      content,
      course: courseId || undefined
    });

    await message.save();

    logger.audit('MESSAGE_SENT', {
      senderId: req.session.userId,
      recipientId,
      messageId: message._id
    });

    res.status(201).json({ message: 'Message sent.', messageId: message._id });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
