'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const config = require('../config');

const execFileAsync = promisify(execFile);

const EXTENSION_PATTERN = /^\.[a-z0-9]{1,8}$/;
const THUMBNAIL_TIMEOUT_MS = 30_000;

/**
 * Storage keys are minted here and only here, so an asset's folder name is
 * always a UUID we chose rather than anything a client sent us.
 *
 * @param {string} originalName
 * @returns {string} a relative folder key, e.g. "a1/b2/a1b2...-uuid"
 */
function newStorageKey(originalName) {
  const id = crypto.randomUUID();
  void originalName;
  return path.posix.join(id.slice(0, 2), id.slice(2, 4), id);
}

/** @param {string} filename @returns {string} */
function safeExtension(filename) {
  const extension = path.extname(String(filename || '')).toLowerCase();
  return EXTENSION_PATTERN.test(extension) ? extension : '.bin';
}

/**
 * Absolute path of one asset's own folder.
 *
 * @param {{ storageKey: string }} asset
 * @returns {string}
 */
function assetDirectory(asset) {
  return path.resolve(config.storage.root, asset.storageKey);
}

/**
 * Resolve a file inside one asset's folder.
 *
 * `relativePath` is allowed to come from a request, so the resolved result is
 * compared against the asset folder before it is handed to fs: a caller that
 * asks for "../../../../etc/passwd" gets a 400 back instead of a file handle.
 *
 * @param {{ storageKey: string }} asset
 * @param {string} relativePath
 * @returns {string} absolute path, guaranteed to sit inside the asset folder
 */
function resolveAssetFile(asset, relativePath) {
  const base = assetDirectory(asset);
  const target = path.resolve(base, String(relativePath || ''));
  if (target !== base && !target.startsWith(base + path.sep)) {
    const error = new Error('requested file is not part of this asset');
    error.status = 400;
    error.expose = true;
    throw error;
  }
  return target;
}

/**
 * Open one generated rendition for streaming.
 *
 * @param {{ storageKey: string }} asset
 * @param {string} variant
 */
async function openRendition(asset, variant) {
  if (!Object.prototype.hasOwnProperty.call(config.storage.renditions, variant)) {
    const error = new Error(`unknown rendition ${variant}`);
    error.status = 404;
    error.expose = true;
    throw error;
  }

  const file = resolveAssetFile(asset, path.join(config.storage.renditionRoot, `${variant}.jpg`));
  const stat = await fsp.stat(file);
  return { path: file, size: stat.size, stream: fs.createReadStream(file) };
}

/**
 * Move an uploaded (or imported) file into the asset folder as the original.
 *
 * @param {string} storageKey minted by newStorageKey()
 * @param {string} filename the name the uploader used, for the extension only
 * @param {string} sourcePath a path we control, in the scratch directory
 */
async function writeOriginal(storageKey, filename, sourcePath) {
  const directory = path.resolve(config.storage.root, storageKey);
  await fsp.mkdir(path.join(directory, config.storage.renditionRoot), { recursive: true });
  const target = path.join(directory, `original${safeExtension(filename)}`);
  await fsp.copyFile(sourcePath, target);
  const stat = await fsp.stat(target);
  return { path: target, size: stat.size };
}

/**
 * Render the thumbnail set for an asset. ffmpeg is spawned without a shell and
 * every argument is passed as its own array entry.
 *
 * @param {string} storageKey
 * @param {string} originalPath
 */
async function renderThumbnails(storageKey, originalPath) {
  const directory = path.resolve(config.storage.root, storageKey, config.storage.renditionRoot);
  await fsp.mkdir(directory, { recursive: true });

  const written = [];
  for (const [variant, width] of Object.entries(config.storage.renditions)) {
    const output = path.join(directory, `${variant}.jpg`);
    await execFileAsync(
      config.storage.ffmpegPath,
      ['-y', '-i', originalPath, '-vf', `scale=${width}:-2`, '-frames:v', '1', output],
      { timeout: THUMBNAIL_TIMEOUT_MS },
    );
    written.push({ variant, width, file: path.relative(config.storage.root, output) });
  }
  return written;
}

module.exports = {
  newStorageKey,
  safeExtension,
  assetDirectory,
  resolveAssetFile,
  openRendition,
  writeOriginal,
  renderThumbnails,
};
