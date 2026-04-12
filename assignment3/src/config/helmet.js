/**
 * Helmet Configuration for EduLearn
 * Configured for: AWS S3 video streaming, Stripe payments, third-party analytics
 */

const helmetConfig = {
  // Content Security Policy - controls which resources can be loaded
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "https://js.stripe.com",           // Stripe payment scripts
        "https://www.google-analytics.com", // Google Analytics
        "https://www.googletagmanager.com"  // Google Tag Manager
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",                  // Allow inline styles for rich text
        "https://fonts.googleapis.com"
      ],
      imgSrc: [
        "'self'",
        "data:",
        "blob:",
        "https://*.s3.amazonaws.com",       // AWS S3 images
        "https://www.google-analytics.com"
      ],
      mediaSrc: [
        "'self'",
        "https://*.s3.amazonaws.com",       // AWS S3 video streaming
        "blob:"                             // For video player blob URLs
      ],
      connectSrc: [
        "'self'",
        "https://api.stripe.com",           // Stripe API calls
        "https://www.google-analytics.com",
        "https://analytics.google.com"
      ],
      frameSrc: [
        "'self'",
        "https://js.stripe.com",           // Stripe iframe for payments
        "https://player.vimeo.com",        // Embedded course materials
        "https://www.youtube.com"          // Embedded course materials
      ],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com"
      ],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: []
    }
  },

  // Prevent clickjacking
  frameguard: { action: 'deny' },

  // Hide X-Powered-By header
  hidePoweredBy: true,

  // Strict Transport Security - force HTTPS
  hsts: {
    maxAge: 31536000,           // 1 year
    includeSubDomains: true,
    preload: true
  },

  // Prevent MIME type sniffing
  noSniff: true,

  // Referrer Policy
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

  // XSS Protection (legacy browsers)
  xssFilter: true,

  // Permissions Policy
  permittedCrossDomainPolicies: { permittedPolicies: 'none' }
};

module.exports = helmetConfig;
