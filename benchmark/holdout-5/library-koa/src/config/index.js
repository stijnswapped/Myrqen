'use strict';

const path = require('node:path');

/**
 * Runtime configuration for the media asset library API.
 *
 * Secrets are deliberately never defaulted: if MEDIA_SESSION_SECRET is absent
 * the session middleware refuses to load rather than signing cookies with a
 * placeholder that would end up in a staging deploy.
 */

/** @param {string|undefined} value @param {number} fallback @returns {number} */
function int(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/** @param {string|undefined} value @param {string[]} fallback @returns {string[]} */
function list(value, fallback) {
  if (typeof value !== 'string' || value.trim().length === 0) return fallback;
  return value
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);
}

module.exports = Object.freeze({
  env: process.env.NODE_ENV || 'development',
  port: int(process.env.PORT, 4300),

  mongo: {
    uri: process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/media_library',
    options: {
      maxPoolSize: int(process.env.MONGO_POOL_SIZE, 10),
      serverSelectionTimeoutMS: 5000,
    },
  },

  session: {
    secret: process.env.MEDIA_SESSION_SECRET,
    issuer: 'media-library.internal',
    audience: 'media-library.web',
    cookieName: 'mlib_sid',
    ttlSeconds: int(process.env.MEDIA_SESSION_TTL, 60 * 60 * 8),
  },

  serviceTokens: {
    secret: process.env.MEDIA_SERVICE_TOKEN_SECRET,
    audience: 'media-library.ingest',
  },

  storage: {
    root: process.env.MEDIA_STORAGE_ROOT || path.join(__dirname, '..', '..', 'var', 'media'),
    renditionRoot: 'renditions',
    renditions: Object.freeze({ thumb_240: 240, thumb_640: 640, preview_1280: 1280 }),
    maxUploadBytes: int(process.env.MEDIA_MAX_UPLOAD_BYTES, 512 * 1024 * 1024),
    ffmpegPath: process.env.FFMPEG_PATH || 'ffmpeg',
  },

  imports: {
    // Partner connectors we have a contract with. Anything else has to go
    // through the manual upload form.
    approvedHosts: Object.freeze(
      list(process.env.MEDIA_IMPORT_HOSTS, ['assets.partner-cdn.example.com', 'dam.contoso.example']),
    ),
    maxBytes: int(process.env.MEDIA_IMPORT_MAX_BYTES, 64 * 1024 * 1024),
    timeoutMs: int(process.env.MEDIA_IMPORT_TIMEOUT_MS, 15000),
  },

  moderation: {
    pageSize: int(process.env.MEDIA_REVIEW_PAGE_SIZE, 100),
    maxCommentLength: 4000,
  },

  web: {
    origin: process.env.MEDIA_WEB_ORIGIN || 'http://localhost:5173',
  },
});
