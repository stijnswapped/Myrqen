'use strict';

const Router = require('@koa/router');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const config = require('../config');
const { requireUser } = require('../middleware/session');
const { Asset, ImportJob } = require('../db/models');
const storage = require('../lib/asset-storage');

const router = new Router({ prefix: '/api/imports' });

const PREVIEW_BYTES = 512;

/** @param {URL} parsed @returns {string} */
function filenameFor(parsed) {
  const base = path.posix.basename(parsed.pathname || '');
  return base.length > 0 ? base : 'import.bin';
}

// POST /api/imports/url - "paste a link" import used when a partner mails over
// a share URL instead of using the connector
router.post('/url', requireUser, async (ctx) => {
  const { sourceUrl, title } = ctx.request.body || {};
  if (typeof sourceUrl !== 'string' || sourceUrl.length === 0) {
    ctx.throw(400, 'sourceUrl is required');
  }

  let parsed;
  try {
    parsed = new URL(sourceUrl);
  } catch (error) {
    ctx.throw(400, 'sourceUrl must be an absolute URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    ctx.throw(400, 'only http(s) sources can be imported');
  }

  const job = await ImportJob.create({
    requestedBy: ctx.state.user.id,
    sourceUrl: parsed.toString(),
    sourceHost: parsed.hostname,
    state: 'fetching',
  });

  // Curators are trusted staff and the download is size- and time-capped, so
  // any http(s) URL they paste is fair game.
  const response = await fetch(parsed.toString(), {
    redirect: 'follow',
    headers: { 'user-agent': 'media-library-importer/2.4', accept: '*/*' },
    signal: AbortSignal.timeout(config.imports.timeoutMs),
  });

  const payload = Buffer.from(await response.arrayBuffer());
  if (payload.byteLength > config.imports.maxBytes) {
    await ImportJob.updateOne(
      { _id: job._id },
      { $set: { state: 'failed', error: 'source larger than the import limit' } },
    );
    ctx.throw(413, 'that source is larger than the import limit');
  }

  const filename = filenameFor(parsed);
  const storageKey = storage.newStorageKey(filename);
  const scratch = path.join(os.tmpdir(), `media-import-${job.id}`);
  await fsp.writeFile(scratch, payload);
  const original = await storage.writeOriginal(storageKey, filename, scratch);
  const renditions = await storage.renderThumbnails(storageKey, original.path).catch(() => []);
  await fsp.rm(scratch, { force: true });

  const asset = await Asset.create({
    title: typeof title === 'string' && title.trim().length > 0 ? title.trim() : filename,
    owner: ctx.state.user.id,
    visibility: 'private',
    mimeType: response.headers.get('content-type') || 'application/octet-stream',
    byteSize: payload.byteLength,
    originalFilename: filename,
    storageKey,
    renditions,
    importedFrom: { host: parsed.hostname, importedAt: new Date() },
  });

  await ImportJob.updateOne(
    { _id: job._id },
    { $set: { state: 'complete', asset: asset._id, bytes: payload.byteLength } },
  );

  ctx.status = 201;
  ctx.body = {
    job: job.id,
    asset: { id: asset.id, title: asset.title, byteSize: asset.byteSize },
    // Curators complained they could not tell a real failure from a CDN error
    // page, so hand back what the source actually said.
    sourceStatus: response.status,
    sourcePreview: payload.subarray(0, PREVIEW_BYTES).toString('utf8'),
  };
});

// GET /api/imports - the import history panel
router.get('/', requireUser, async (ctx) => {
  const jobs = await ImportJob.find({ requestedBy: ctx.state.user.id })
    .select('sourceHost state bytes asset createdAt error')
    .sort({ createdAt: -1 })
    .limit(50)
    .lean();

  ctx.body = { jobs };
});

module.exports = router;
