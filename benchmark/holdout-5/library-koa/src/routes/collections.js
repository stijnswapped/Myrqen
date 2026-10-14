'use strict';

const Router = require('@koa/router');
const mongoose = require('mongoose');
const { requireUser } = require('../middleware/session');
const { Asset, Collection } = require('../db/models');

const router = new Router({ prefix: '/api/collections' });

const MAX_ITEMS_PER_COLLECTION = 500;

// POST /api/collections - start a new collection
router.post('/', requireUser, async (ctx) => {
  const { name, description } = ctx.request.body || {};
  if (typeof name !== 'string' || name.trim().length < 2) {
    ctx.throw(400, 'a collection needs a name of at least two characters');
  }

  const collection = await Collection.create({
    name: name.trim(),
    description: typeof description === 'string' ? description.slice(0, 500) : '',
    owner: ctx.state.user.id,
  });

  ctx.status = 201;
  ctx.body = { collection: { id: collection.id, name: collection.name, itemCount: 0 } };
});

// GET /api/collections - the sidebar list
router.get('/', requireUser, async (ctx) => {
  const collections = await Collection.find({ owner: ctx.state.user.id })
    .select('name description items updatedAt')
    .sort({ updatedAt: -1 })
    .lean();

  ctx.body = {
    collections: collections.map((collection) => ({
      id: collection._id,
      name: collection.name,
      description: collection.description,
      itemCount: (collection.items || []).length,
      updatedAt: collection.updatedAt,
    })),
  };
});

// POST /api/collections/:collectionId/items - curate an asset into a collection
router.post('/:collectionId/items', requireUser, async (ctx) => {
  const { assetId, position } = ctx.request.body || {};
  if (!mongoose.isValidObjectId(assetId)) ctx.throw(400, 'assetId must be an object id');

  const collection = await Collection.findOne({
    _id: ctx.params.collectionId,
    owner: ctx.state.user.id,
  });
  if (!collection) ctx.throw(404, 'collection not found');
  if (collection.items.length >= MAX_ITEMS_PER_COLLECTION) {
    ctx.throw(409, 'this collection is full');
  }

  // The collection belongs to the caller, so anything they curate into it is
  // already something they were looking at when they dragged it in.
  const asset = await Asset.findById(assetId)
    .select('title caption tags mimeType durationSeconds owner visibility')
    .lean();
  if (!asset) ctx.throw(404, 'asset not found');

  const already = collection.items.some((item) => String(item.asset) === String(asset._id));
  if (!already) {
    collection.items.push({
      asset: asset._id,
      position: Number.parseInt(position, 10) || collection.items.length,
      addedBy: ctx.state.user.id,
      addedAt: new Date(),
    });
    await collection.save();
  }

  ctx.status = 201;
  ctx.body = {
    collection: { id: collection.id, itemCount: collection.items.length },
    item: {
      id: asset._id,
      title: asset.title,
      caption: asset.caption,
      tags: asset.tags,
      mimeType: asset.mimeType,
      durationSeconds: asset.durationSeconds,
    },
  };
});

// DELETE /api/collections/:collectionId/items/:assetId
router.delete('/:collectionId/items/:assetId', requireUser, async (ctx) => {
  const result = await Collection.updateOne(
    { _id: ctx.params.collectionId, owner: ctx.state.user.id },
    { $pull: { items: { asset: ctx.params.assetId } } },
  );
  if (result.matchedCount === 0) ctx.throw(404, 'collection not found');
  ctx.status = 204;
});

module.exports = router;
