'use strict';

const mongoose = require('mongoose');
const config = require('../config');

const { Schema } = mongoose;

/* -------------------------------------------------------------------------- */
/* people                                                                     */
/* -------------------------------------------------------------------------- */

const UserSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true, select: false },
    role: {
      type: String,
      enum: ['viewer', 'curator', 'moderator', 'admin'],
      default: 'viewer',
      index: true,
    },
    disabledAt: { type: Date, default: null },
  },
  { timestamps: true },
);

UserSchema.methods.toJSON = function toJSON() {
  return { id: this.id, name: this.name, email: this.email, role: this.role };
};

/* -------------------------------------------------------------------------- */
/* assets                                                                     */
/* -------------------------------------------------------------------------- */

const GrantSchema = new Schema(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    level: { type: String, enum: ['view', 'comment', 'edit'], default: 'view' },
    grantedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    expiresAt: { type: Date, default: null },
  },
  { _id: false },
);

const AssetSchema = new Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 240 },
    caption: { type: String, default: '', trim: true, maxlength: 2000 },
    owner: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    visibility: {
      type: String,
      enum: ['private', 'team', 'public'],
      default: 'private',
      index: true,
    },
    tags: [{ type: String, lowercase: true, trim: true }],
    mimeType: { type: String, default: 'application/octet-stream' },
    byteSize: { type: Number, default: 0 },
    durationSeconds: { type: Number, default: null },
    originalFilename: { type: String, default: '' },
    // Minted by lib/asset-storage.newStorageKey(); this is the asset's folder
    // underneath config.storage.root and is never taken from a request.
    storageKey: { type: String, required: true, unique: true },
    renditions: [{ variant: String, width: Number, file: String, _id: false }],
    grants: [GrantSchema],
    importedFrom: { host: String, importedAt: Date },
  },
  { timestamps: true },
);

AssetSchema.index({ tags: 1, visibility: 1 });
AssetSchema.index({ owner: 1, createdAt: -1 });

const TAG_PATTERN = /^[a-z0-9][a-z0-9 _-]{0,47}$/;
const MAX_SEARCH_TAGS = 8;
const DEFAULT_SEARCH_LIMIT = 25;
const MAX_SEARCH_LIMIT = 100;

/**
 * The clauses that decide whether a viewer may see an asset at all: they own
 * it, it is public, or somebody handed them a grant that has not lapsed yet.
 *
 * @param {string} viewerId
 * @returns {object[]} clauses meant for an `$or`
 */
AssetSchema.statics.visibilityFilter = function visibilityFilter(viewerId) {
  return [
    { owner: viewerId },
    { visibility: 'public' },
    {
      grants: {
        $elemMatch: {
          user: viewerId,
          $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
        },
      },
    },
  ];
};

/**
 * Tag search for the asset browser.
 *
 * Callers hand us whatever the client posted, so every candidate tag has to
 * survive a `typeof` check and the tag pattern before it can become part of the
 * query. A payload such as `{"tag": {"$ne": null}}` therefore collapses to an
 * empty tag list and matches nothing, instead of arriving at Mongo as an
 * operator document.
 *
 * @param {unknown} rawTags
 * @param {string} viewerId
 * @param {unknown} rawLimit
 */
AssetSchema.statics.searchByTags = function searchByTags(rawTags, viewerId, rawLimit) {
  const candidates = Array.isArray(rawTags) ? rawTags : [rawTags];
  const tags = candidates
    .filter((candidate) => typeof candidate === 'string')
    .map((candidate) => candidate.trim().toLowerCase())
    .filter((candidate) => TAG_PATTERN.test(candidate))
    .slice(0, MAX_SEARCH_TAGS);

  if (tags.length === 0) return Promise.resolve([]);

  const limit = Math.min(
    Math.max(Number.parseInt(rawLimit, 10) || DEFAULT_SEARCH_LIMIT, 1),
    MAX_SEARCH_LIMIT,
  );

  return this.find({ tags: { $all: tags }, $or: this.visibilityFilter(viewerId) })
    .select('title caption tags mimeType durationSeconds owner visibility createdAt')
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean()
    .exec();
};

/* -------------------------------------------------------------------------- */
/* curation                                                                   */
/* -------------------------------------------------------------------------- */

const CollectionSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 160 },
    description: { type: String, default: '', maxlength: 500 },
    owner: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    items: [
      {
        asset: { type: Schema.Types.ObjectId, ref: 'Asset', required: true },
        position: { type: Number, default: 0 },
        addedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        addedAt: { type: Date, default: Date.now },
        _id: false,
      },
    ],
  },
  { timestamps: true },
);

const PlaylistSchema = new Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 160 },
    owner: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    visibility: { type: String, enum: ['private', 'team'], default: 'private' },
    entries: [
      {
        asset: { type: Schema.Types.ObjectId, ref: 'Asset', required: true },
        position: { type: Number, default: 0 },
        startAtSeconds: { type: Number, default: 0 },
        addedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        _id: false,
      },
    ],
  },
  { timestamps: true },
);

const CommentSchema = new Schema(
  {
    asset: { type: Schema.Types.ObjectId, ref: 'Asset', required: true, index: true },
    author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    body: {
      type: String,
      required: true,
      trim: true,
      maxlength: config.moderation.maxCommentLength,
    },
    status: {
      type: String,
      enum: ['pending', 'published', 'rejected'],
      default: 'pending',
      index: true,
    },
    reviewedBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    reviewedAt: { type: Date, default: null },
  },
  { timestamps: true },
);

const ImportJobSchema = new Schema(
  {
    requestedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    sourceUrl: { type: String, required: true },
    sourceHost: { type: String, required: true, index: true },
    state: {
      type: String,
      enum: ['fetching', 'complete', 'failed'],
      default: 'fetching',
      index: true,
    },
    bytes: { type: Number, default: 0 },
    asset: { type: Schema.Types.ObjectId, ref: 'Asset', default: null },
    error: { type: String, default: null },
  },
  { timestamps: true },
);

const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Asset = mongoose.models.Asset || mongoose.model('Asset', AssetSchema);
const Collection = mongoose.models.Collection || mongoose.model('Collection', CollectionSchema);
const Playlist = mongoose.models.Playlist || mongoose.model('Playlist', PlaylistSchema);
const Comment = mongoose.models.Comment || mongoose.model('Comment', CommentSchema);
const ImportJob = mongoose.models.ImportJob || mongoose.model('ImportJob', ImportJobSchema);

async function connect() {
  mongoose.set('strictQuery', true);
  await mongoose.connect(config.mongo.uri, config.mongo.options);
  return mongoose.connection;
}

module.exports = {
  mongoose,
  connect,
  User,
  Asset,
  Collection,
  Playlist,
  Comment,
  ImportJob,
};
