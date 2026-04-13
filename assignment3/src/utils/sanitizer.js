
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');
const { body, param, query } = require('express-validator');

// Create DOMPurify instance
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);


const sanitizeRichText = (dirty) => {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'p', 'br', 'hr',
      'strong', 'em', 'b', 'i', 'u', 's',
      'ul', 'ol', 'li',
      'blockquote', 'pre', 'code',
      'a', 'img',
      'table', 'thead', 'tbody', 'tr', 'th', 'td',
      'div', 'span', 'sub', 'sup'
    ],
    ALLOWED_ATTR: [
      'href', 'target', 'rel',
      'src', 'alt', 'width', 'height',
      'class', 'id',
      'colspan', 'rowspan'
    ],
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: ['target'],
    // Force all links to open in new tab with noopener
    FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'input', 'textarea', 'select'],
    FORBID_ATTR: ['onerror', 'onclick', 'onload', 'onmouseover', 'onfocus', 'onblur']
  });
};


const sanitizePlainText = (dirty) => {
  if (typeof dirty !== 'string') return '';
  return DOMPurify.sanitize(dirty, { ALLOWED_TAGS: [] }).trim();
};

const sanitizeQuizContent = (dirty) => {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['strong', 'em', 'code', 'pre', 'sub', 'sup', 'br', 'p'],
    ALLOWED_ATTR: [],
    ALLOW_DATA_ATTR: false
  });
};

const sanitizeMessage = (dirty) => {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'a', 'code', 'pre', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
    ALLOW_DATA_ATTR: false
  });
};


const validateCourseInput = [
  body('title')
    .trim()
    .isLength({ min: 3, max: 200 })
    .withMessage('Title must be between 3 and 200 characters')
    .customSanitizer(sanitizePlainText),
  body('description')
    .isLength({ min: 10, max: 50000 })
    .withMessage('Description must be between 10 and 50000 characters')
    .customSanitizer(sanitizeRichText),
  body('price')
    .optional()
    .isFloat({ min: 0, max: 99999 })
    .withMessage('Price must be between 0 and 99999')
    .toFloat(),
  body('category')
    .trim()
    .isIn(['programming', 'design', 'business', 'science', 'math', 'language', 'other'])
    .withMessage('Invalid category')
];

const validateQuizInput = [
  body('title')
    .trim()
    .isLength({ min: 3, max: 200 })
    .withMessage('Title must be between 3 and 200 characters')
    .customSanitizer(sanitizePlainText),
  body('questions').isArray({ min: 1, max: 100 })
    .withMessage('Quiz must have between 1 and 100 questions'),
  body('questions.*.question')
    .isLength({ min: 1, max: 5000 })
    .withMessage('Question text is required')
    .customSanitizer(sanitizeQuizContent),
  body('questions.*.options')
    .isArray({ min: 2, max: 10 })
    .withMessage('Each question must have 2-10 options'),
  body('questions.*.options.*')
    .isLength({ min: 1, max: 1000 })
    .customSanitizer(sanitizePlainText),
  body('questions.*.correctAnswer')
    .isInt({ min: 0 })
    .withMessage('Correct answer index is required')
];

const validateMessageInput = [
  body('subject')
    .trim()
    .isLength({ min: 1, max: 200 })
    .withMessage('Subject is required (max 200 chars)')
    .customSanitizer(sanitizePlainText),
  body('content')
    .isLength({ min: 1, max: 10000 })
    .withMessage('Message content is required (max 10000 chars)')
    .customSanitizer(sanitizeMessage),
  body('recipientId')
    .isMongoId()
    .withMessage('Invalid recipient ID')
];

const validateProfileInput = [
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Name can only contain letters, spaces, hyphens, and apostrophes')
    .customSanitizer(sanitizePlainText),
  body('bio')
    .optional()
    .isLength({ max: 2000 })
    .withMessage('Bio must be under 2000 characters')
    .customSanitizer(sanitizePlainText),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email format')
];

const validateMongoId = [
  param('id').isMongoId().withMessage('Invalid ID format')
];

module.exports = {
  sanitizeRichText,
  sanitizePlainText,
  sanitizeQuizContent,
  sanitizeMessage,
  validateCourseInput,
  validateQuizInput,
  validateMessageInput,
  validateProfileInput,
  validateMongoId
};
