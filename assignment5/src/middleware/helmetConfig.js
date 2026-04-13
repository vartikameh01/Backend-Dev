'use strict';

const helmet = require('helmet');

/**
 * helmetConfig
 * Returns a fully-configured Helmet middleware stack for a financial application.
 *
 * Key security headers applied (Task 4):
 * - Content-Security-Policy: strict allowlist — blocks inline scripts and unknown origins
 * - Strict-Transport-Security: 2-year HSTS with preload
 * - X-Frame-Options: DENY — prevents clickjacking
 * - X-Content-Type-Options: nosniff
 * - Referrer-Policy: no-referrer — no URL leakage to third parties
 * - Permissions-Policy: disables geolocation, camera, microphone
 *
 * @returns {function[]} Array of Express middleware
 */
function helmetConfig() {
  return [
    // Core security headers
    helmet({
      // HSTS: 2 years, include subdomains, allow preload registration
      hsts: {
        maxAge: 63_072_000,
        includeSubDomains: true,
        preload: true,
      },
      // Referrer policy: no information leaked to third parties
      referrerPolicy: { policy: 'no-referrer' },
      // Prevent MIME sniffing
      noSniff: true,
      // Prevent clickjacking
      frameguard: { action: 'deny' },
      // XSS filter header (legacy browsers)
      xssFilter: true,
      // Hide X-Powered-By
      hidePoweredBy: true,
      // Content Security Policy is set separately below for readability
      contentSecurityPolicy: false,
    }),

    // Strict Content Security Policy
    helmet.contentSecurityPolicy({
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: [
          "'self'",
          // Allow inline scripts only with a nonce (add nonce middleware if using SSR)
        ],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        upgradeInsecureRequests: [],
      },
    }),

    // Permissions Policy
    (req, res, next) => {
      res.setHeader(
        'Permissions-Policy',
        'geolocation=(), camera=(), microphone=(), payment=()',
      );
      next();
    },
  ];
}

module.exports = helmetConfig;
