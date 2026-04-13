'use strict';

/**
 * helmetConfig.js
 * Task 5: Helmet with healthcare-specific security headers.
 *
 * Key considerations for a healthcare platform:
 * - No framing (clickjacking protection for login/PHI pages)
 * - Strict CSP: no inline scripts, strict trusted sources only
 * - HSTS with long max-age (HIPAA recommends encryption in transit)
 * - Referrer-Policy: no-referrer to avoid leaking patient info in URLs
 * - Permissions-Policy: disable camera/mic/geolocation by default
 */

const helmet = require('helmet');

function configureHelmet(app) {
  // ─── Content Security Policy ──────────────────────────────────────────────
  const cspDirectives = {
    defaultSrc: ["'self'"],
    scriptSrc:  ["'self'"],             // no 'unsafe-inline', no CDNs
    styleSrc:   ["'self'", "'unsafe-inline'"], // inline styles needed for most UIs
    imgSrc:     ["'self'", 'data:'],    // allow data URIs for local images
    fontSrc:    ["'self'"],
    connectSrc: ["'self'"],
    mediaSrc:   ["'none'"],
    objectSrc:  ["'none'"],             // no Flash / plugins
    frameSrc:   ["'none'"],
    frameAncestors: ["'none'"],         // clickjacking prevention
    formAction: ["'self'"],
    baseUri:    ["'self'"],
    upgradeInsecureRequests: [],
  };

  app.use(
    helmet({
      // ── Content-Security-Policy ──────────────────────────────────────────
      contentSecurityPolicy: {
        directives: cspDirectives,
        reportOnly: false,
      },

      // ── HTTP Strict Transport Security ───────────────────────────────────
      // 2-year max-age, include subdomains, preload-ready
      // HIPAA requires encryption in transit; HSTS enforces HTTPS
      hsts: {
        maxAge: 63072000,
        includeSubDomains: true,
        preload: true,
      },

      // ── X-Frame-Options ──────────────────────────────────────────────────
      frameguard: { action: 'deny' },

      // ── X-Content-Type-Options ───────────────────────────────────────────
      noSniff: true,

      // ── Referrer-Policy ───────────────────────────────────────────────────
      // 'no-referrer' ensures patient names/IDs in URLs aren't leaked to 3rd parties
      referrerPolicy: { policy: 'no-referrer' },

      // ── X-XSS-Protection ─────────────────────────────────────────────────
      // Deprecated header, but still enabled for legacy browsers
      xssFilter: true,

      // ── X-DNS-Prefetch-Control ────────────────────────────────────────────
      dnsPrefetchControl: { allow: false },

      // ── X-Download-Options ───────────────────────────────────────────────
      ieNoOpen: true,

      // ── X-Permitted-Cross-Domain-Policies ─────────────────────────────────
      permittedCrossDomainPolicies: { permittedPolicies: 'none' },

      // ── Cross-Origin-Embedder-Policy ──────────────────────────────────────
      crossOriginEmbedderPolicy: true,

      // ── Cross-Origin-Opener-Policy ────────────────────────────────────────
      crossOriginOpenerPolicy: { policy: 'same-origin' },

      // ── Cross-Origin-Resource-Policy ──────────────────────────────────────
      crossOriginResourcePolicy: { policy: 'same-origin' },

      // ── Origin-Agent-Cluster ─────────────────────────────────────────────
      originAgentCluster: true,
    })
  );

  // ── Permissions-Policy (not in Helmet core — add manually) ────────────────
  // Disable camera, microphone, geolocation — not needed by a booking portal
  app.use((_req, res, next) => {
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=()'
    );
    next();
  });
}

module.exports = { configureHelmet };
