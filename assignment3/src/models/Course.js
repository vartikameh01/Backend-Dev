/**
 * Course Model - EduLearn
 */

const mongoose = require('mongoose');

const courseSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Course title is required'],
    trim: true,
    minlength: 3,
    maxlength: 200
  },
  description: {
    type: String,
    required: [true, 'Course description is required'],
    minlength: 10,
    maxlength: 50000
    // Stored as sanitized HTML (rich text)
  },
  instructor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  category: {
    type: String,
    enum: ['programming', 'design', 'business', 'science', 'math', 'language', 'other'],
    required: true
  },
  price: {
    type: Number,
    default: 0,
    min: 0,
    max: 99999
  },
  isPremium: {
    type: Boolean,
    default: false
  },
  enrolledStudents: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  videos: [{
    title: { type: String, required: true },
    url: { type: String, required: true },
    duration: { type: Number },  // in seconds
    order: { type: Number }
  }],
  materials: [{
    title: { type: String },
    filename: { type: String },
    originalName: { type: String },
    mimetype: { type: String },
    size: { type: Number },
    uploadedAt: { type: Date, default: Date.now }
  }],
  quizzes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Quiz'
  }],
  isPublished: {
    type: Boolean,
    default: false
  },
  rating: {
    average: { type: Number, default: 0, min: 0, max: 5 },
    count: { type: Number, default: 0 }
  }
}, {
  timestamps: true
});

// Indexes
courseSchema.index({ instructor: 1 });
courseSchema.index({ category: 1 });
courseSchema.index({ title: 'text', description: 'text' });
courseSchema.index({ isPublished: 1 });

module.exports = mongoose.model('Course', courseSchema);
