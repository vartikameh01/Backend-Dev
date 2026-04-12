'use strict';

require('dotenv').config();

const app = require('./src/app');
const { connectDB } = require('./src/config/database');
const logger = require('./src/utils/logger');

const PORT = parseInt(process.env.PORT, 10) || 3000;

async function start() {
  await connectDB();
  app.listen(PORT, () => {
    logger.info(`QuickBank API running on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
  });
}

// ─── Graceful shutdown ────────────────────────────────────────────────────────
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received — shutting down gracefully');
  const { disconnectDB } = require('./src/config/database');
  await disconnectDB();
  process.exit(0);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled promise rejection', { reason: String(reason) });
  // Don't exit — log and continue; a crash loop is worse than a degraded state
});

start().catch((err) => {
  logger.error('Failed to start server', { error: err.message });
  process.exit(1);
});
