'use strict';

const Router = require('@koa/router');
const mongoose = require('mongoose');
const { requireUser } = require('../middleware/session');
const { Asset, Playlist } = require('../db/models');

const router = new Router({ prefix: '/api/playlists' });

const MAX_ENTRIES_PER_PLAYLIST = 300;

// POST /api/playlists - a playlist is an ordered run of timed assets
router.post('/', requireUser, async (ctx) => {
  const { name, visibility } = ctx.request.body || {};
  if (typeof name !== 'string' || name.trim().length < 2) {
    ctx.throw(400, 'a playlist needs a name of at least two characters');
  }

  const playlist = await Playlist.create({
    name: name.trim(),
    visibility: visibility === 'team' ? 'team' : 'private',
    owner: ctx.state.user.id,
  });

  ctx.status = 201;
  ctx.body = { playlist: { id: playlist.id, name: playlist.name, entryCount: 0 } };
});

// POST /api/playlists/:playlistId/entries - append an asset to the run
router.post('/:playlistId/entries', requireUser, async (ctx) => {
  const { assetId, position, startAtSeconds } = ctx.request.body || {};
  if (!mongoose.isValidObjectId(assetId)) ctx.throw(400, 'assetId must be an object id');

  const playlist = await Playlist.findOne({
    _id: ctx.params.playlistId,
    owner: ctx.state.user.id,
  });
  if (!playlist) ctx.throw(404, 'playlist not found');
  if (playlist.entries.length >= MAX_ENTRIES_PER_PLAYLIST) {
    ctx.throw(409, 'this playlist is full');
  }

  // Owning the playlist says nothing about the asset, so the asset lookup
  // carries the viewer's visibility clauses: an asset that was never shared
  // with this person simply does not come back and the append 404s.
  const asset = await Asset.findOne({
    _id: assetId,
    $or: Asset.visibilityFilter(ctx.state.user.id),
  })
    .select('title caption tags mimeType durationSeconds owner visibility')
    .lean();
  if (!asset) ctx.throw(404, 'asset not found');

  playlist.entries.push({
    asset: asset._id,
    position: Number.parseInt(position, 10) || playlist.entries.length,
    startAtSeconds: Math.max(Number.parseInt(startAtSeconds, 10) || 0, 0),
    addedBy: ctx.state.user.id,
  });
  await playlist.save();

  ctx.status = 201;
  ctx.body = {
    playlist: { id: playlist.id, entryCount: playlist.entries.length },
    entry: {
      id: asset._id,
      title: asset.title,
      caption: asset.caption,
      tags: asset.tags,
      mimeType: asset.mimeType,
      durationSeconds: asset.durationSeconds,
    },
  };
});

// GET /api/playlists/:playlistId - the player fetches the whole run at once
router.get('/:playlistId', requireUser, async (ctx) => {
  const playlist = await Playlist.findOne({
    _id: ctx.params.playlistId,
    owner: ctx.state.user.id,
  })
    .populate('entries.asset', 'title mimeType durationSeconds visibility')
    .lean();
  if (!playlist) ctx.throw(404, 'playlist not found');

  ctx.body = {
    playlist: {
      id: playlist._id,
      name: playlist.name,
      entries: (playlist.entries || [])
        .slice()
        .sort((a, b) => a.position - b.position)
        .map((entry) => ({
          id: entry.asset && entry.asset._id,
          title: entry.asset && entry.asset.title,
          mimeType: entry.asset && entry.asset.mimeType,
          startAtSeconds: entry.startAtSeconds,
        })),
    },
  };
});

module.exports = router;
