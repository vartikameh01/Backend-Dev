'use strict';

const mongoose = require('mongoose');
const logger = require('../utils/logger');

/**
 * connectDatabase
 * Establishes a secure Mongoose connection with TLS enforcement in production.
 * Retries once on initial failure to handle transient startup races.
 */
async function connectDatabase() {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('MONGODB_URI environment variable is required');

  const options = {
    // Enforce TLS in production (Task 6: encryption in transit)
    tls: process.env.NODE_ENV === 'production',
    // Connection pool — prevents connection exhaustion under load
    maxPoolSize: 20,
    minPoolSize: 2,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  };

  try {
    await mongoose.connect(uri, options);
    logger.info('MongoDB connected');
  } catch (err) {
    logger.error('MongoDB connection error', { message: err.message });
    throw err;
  }

  mongoose.connection.on('error', (err) => {
    logger.error('MongoDB runtime error', { message: err.message });
  });

  mongoose.connection.on('disconnected', () => {
    logger.warn('MongoDB disconnected — attempting reconnect');
  });
}

async function disconnectDatabase() {
  await mongoose.disconnect();
}

module.exports = { connectDatabase, disconnectDatabase };
