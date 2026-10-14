'use strict';

const Router = require('@koa/router');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const config = require('../config');
const { requireUser } = require('../middleware/session');
const { Asset } = require('../db/models');
const storage = require('../lib/asset-storage');

const router = new Router({ prefix: '/api/assets' });

const CONTENT_TYPES = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.mp4': 'video/mp4',
  '.mov': 'video/quicktime',
  '.mp3': 'audio/mpeg',
};

const DEFAULT_FILE = 'renditions/thumb_640.jpg';

/**
 * Load an asset the caller is actually allowed to see. The visibility clauses
 * live in the query itself so a private asset never comes back at all.
 *
 * @param {import('koa').Context} ctx
 */
async function loadVisibleAsset(ctx) {
  const asset = await Asset.findOne({
    _id: ctx.params.assetId,
    $or: Asset.visibilityFilter(ctx.state.user.id),
  })
    .select('title caption storageKey originalFilename mimeType byteSize owner visibility renditions')
    .lean();

  if (!asset) ctx.throw(404, 'asset not found');
  return asset;
}

// GET /api/assets/:assetId - the metadata the viewer pane needs
router.get('/:assetId', requireUser, async (ctx) => {
  const asset = await loadVisibleAsset(ctx);
  ctx.body = {
    asset: {
      id: asset._id,
      title: asset.title,
      caption: asset.caption,
      mimeType: asset.mimeType,
      byteSize: asset.byteSize,
      visibility: asset.visibility,
      renditions: (asset.renditions || []).map((rendition) => rendition.variant),
    },
  };
});

// GET /api/assets/:assetId/file?file=renditions/thumb_240.jpg
// The player asks for a specific file so it can pick a rendition that matches
// the device pixel ratio, and falls back to the 640px thumbnail.
router.get('/:assetId/file', requireUser, async (ctx) => {
  const asset = await loadVisibleAsset(ctx);
  const requested =
    typeof ctx.query.file === 'string' && ctx.query.file.length > 0 ? ctx.query.file : DEFAULT_FILE;

  // storage.assetDirectory() pins us to this asset's own UUID folder, so the
  // player may ask for whatever it likes underneath it.
  const filePath = path.join(storage.assetDirectory(asset), requested);

  const stat = await fsp.stat(filePath).catch(() => null);
  if (!stat || !stat.isFile()) ctx.throw(404, 'that rendition has not been generated yet');

  ctx.type = CONTENT_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
  ctx.length = stat.size;
  ctx.set('cache-control', 'private, max-age=300');
  ctx.body = fs.createReadStream(filePath);
});

// GET /api/assets/:assetId/renditions - which variants exist on disk today
router.get('/:assetId/renditions', requireUser, async (ctx) => {
  const asset = await loadVisibleAsset(ctx);
  const available = [];

  for (const variant of Object.keys(config.storage.renditions)) {
    try {
      const rendition = await storage.openRendition(asset, variant);
      rendition.stream.destroy();
      available.push({ variant, bytes: rendition.size });
    } catch (error) {
      if (error.code !== 'ENOENT' && error.status !== 404) throw error;
    }
  }

  ctx.body = { assetId: asset._id, renditions: available };
});


const OBJECT_ID_PATTERN = /^[a-f0-9]{24}$/i;
const GRANT_LEVELS = ['view', 'comment', 'edit'];

// PUT /api/assets/:assetId/grants - share one asset with a colleague. Only the
// owner may hand out access, so a grantee cannot re-share what was shared with
// them.
router.put('/:assetId/grants', requireUser, async (ctx) => {
  const { userId, level, expiresAt } = ctx.request.body || {};
  if (typeof userId !== 'string' || !OBJECT_ID_PATTERN.test(userId)) {
    ctx.throw(400, 'userId must be an object id');
  }
  if (!GRANT_LEVELS.includes(level)) ctx.throw(400, `level must be one of ${GRANT_LEVELS}`);

  const asset = await Asset.findOne({ _id: ctx.params.assetId, owner: ctx.state.user.id });
  if (!asset) ctx.throw(404, 'asset not found');

  asset.grants = asset.grants.filter((grant) => String(grant.user) !== userId);
  asset.grants.push({
    user: userId,
    level,
    grantedBy: ctx.state.user.id,
    expiresAt: expiresAt ? new Date(expiresAt) : null,
  });
  await asset.save();

  ctx.body = { assetId: asset.id, grants: asset.grants.length };
});

module.exports = router;
