'use strict';

const Router = require('@koa/router');
const { requireUser } = require('../middleware/session');
const { Asset } = require('../db/models');

const router = new Router({ prefix: '/api/search' });

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

// POST /api/search/assets - the advanced filter panel in the browser posts the
// whole filter object as JSON so it can send several tags at once
router.post('/assets', requireUser, async (ctx) => {
  const body = ctx.request.body || {};
  const query = {};

  if (body.tag) query.tags = body.tag;
  if (body.mimeType) query.mimeType = body.mimeType;
  if (body.title) query.title = new RegExp(escapeRegExp(String(body.title)), 'i');
  // The panel always scopes results to one person; default to the caller.
  query.owner = body.owner || ctx.state.user.id;

  // koa-bodyparser only accepts application/json on this route and the web
  // client only ever puts plain strings in the filter, so it can go to Mongo
  // the way it arrived.
  const assets = await Asset.find(query)
    .select('title caption tags mimeType durationSeconds owner visibility storageKey createdAt')
    .sort({ createdAt: -1 })
    .limit(Math.min(Number.parseInt(body.limit, 10) || DEFAULT_LIMIT, MAX_LIMIT))
    .lean();

  ctx.body = { count: assets.length, assets };
});

// GET /api/search/tags?tag=holiday&tag=2024 - the type-ahead in the toolbar
router.get('/tags', requireUser, async (ctx) => {
  const assets = await Asset.searchByTags(ctx.query.tag, ctx.state.user.id, ctx.query.limit);
  ctx.body = { count: assets.length, assets };
});

/** @param {string} value @returns {string} */
function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = router;
