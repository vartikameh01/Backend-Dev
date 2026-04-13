'use strict';

const mongoose = require('mongoose');
const logger = require('../utils/logger');

/**
 * connectDB
 * Establishes a hardened Mongoose connection.
 * - TLS enforced in production
 * - autoIndex disabled in production to avoid uncontrolled index creation
 */
async function connectDB() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('MONGODB_URI environment variable is not set');

  const options = {
    autoIndex: process.env.NODE_ENV !== 'production',
    serverSelectionTimeoutMS: 5000,
  };

  // Enforce TLS in production
  if (process.env.NODE_ENV === 'production') {
    options.tls = true;
    options.tlsAllowInvalidCertificates = false;
  }

  mongoose.connection.on('connected', () => logger.info('MongoDB connected'));
  mongoose.connection.on('error', (err) => logger.error('MongoDB error', { error: err.message }));
  mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected'));

  await mongoose.connect(uri, options);
}

/**
 * disconnectDB
 * Gracefully closes the database connection.
 */
async function disconnectDB() {
  await mongoose.connection.close();
  logger.info('MongoDB connection closed');
}

module.exports = { connectDB, disconnectDB };
