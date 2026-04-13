/**
 * Quiz Model - EduLearn
 * Secure quiz submission with server-side validation
 */

const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
  question: {
    type: String,
    required: true,
    maxlength: 5000
  },
  options: [{
    type: String,
    required: true,
    maxlength: 1000
  }],
  correctAnswer: {
    type: Number,
    required: true,
    min: 0
  },
  points: {
    type: Number,
    default: 1,
    min: 0,
    max: 100
  }
});

const submissionSchema = new mongoose.Schema({
  student: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  answers: [{
    questionIndex: Number,
    selectedOption: Number
  }],
  score: {
    type: Number,
    required: true
  },
  maxScore: {
    type: Number,
    required: true
  },
  percentage: {
    type: Number,
    required: true
  },
  submittedAt: {
    type: Date,
    default: Date.now,
    immutable: true  // Prevent modification after submission
  },
  // Server-side hash of answers at submission time to detect tampering
  answerHash: {
    type: String,
    required: true
  }
});

const quizSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    minlength: 3,
    maxlength: 200
  },
  course: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Course',
    required: true
  },
  instructor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  questions: {
    type: [questionSchema],
    validate: [arr => arr.length >= 1 && arr.length <= 100, 'Quiz must have 1-100 questions']
  },
  submissions: [submissionSchema],
  timeLimit: {
    type: Number,  // in minutes
    min: 1,
    max: 480,
    default: 30
  },
  maxAttempts: {
    type: Number,
    default: 3,
    min: 1,
    max: 10
  },
  isPublished: {
    type: Boolean,
    default: false
  },
  dueDate: {
    type: Date
  }
}, {
  timestamps: true
});

// Indexes
quizSchema.index({ course: 1 });
quizSchema.index({ instructor: 1 });
quizSchema.index({ 'submissions.student': 1 });

module.exports = mongoose.model('Quiz', quizSchema);
