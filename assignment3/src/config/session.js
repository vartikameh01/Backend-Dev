/**
 * Session Configuration with MongoStore
 * Secure session storage replacing in-memory sessions
 */

const MongoStore = require('connect-mongo');

const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'edulearn.sid',  // Custom cookie name (hide technology)

  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: parseInt(process.env.SESSION_MAX_AGE) / 1000 || 3600, // 1 hour default
    autoRemove: 'native',
    crypto: {
      secret: process.env.ENCRYPTION_KEY
    },
    touchAfter: 24 * 3600 // Lazy session update (once per day unless data changes)
  }),

  cookie: {
    secure: process.env.NODE_ENV === 'production',        // HTTPS only in production
    httpOnly: true,                                        // Prevent client-side JS access
    maxAge: parseInt(process.env.SESSION_MAX_AGE) || 3600000, // 1 hour
    sameSite: 'strict',                                    // CSRF protection
    domain: process.env.COOKIE_DOMAIN || undefined,
    path: '/'
  }
};

module.exports = sessionConfig;
