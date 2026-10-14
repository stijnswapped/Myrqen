'use strict';

const Router = require('@koa/router');
const dns = require('node:dns/promises');
const fsp = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const config = require('../config');
const { requireUser, requireRole } = require('../middleware/session');
const { Asset, ImportJob } = require('../db/models');
const storage = require('../lib/asset-storage');

const router = new Router({ prefix: '/api/connectors' });

const APPROVED_HOSTS = new Set(config.imports.approvedHosts);

/**
 * True for anything that is not routable on the public internet: loopback, the
 * link-local metadata range, and the RFC1918 / RFC6598 / unique-local blocks.
 *
 * @param {string} address
 * @returns {boolean}
 */
function isPrivateAddress(address) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  const normalised = address.toLowerCase();
  if (normalised === '::' || normalised === '::1') return true;
  return /^(fc|fd|fe8|fe9|fea|feb)/.test(normalised);
}

// POST /api/connectors/pull - pull one object from a contracted partner DAM
router.post('/pull', requireUser, requireRole('curator'), async (ctx) => {
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

  // Three things have to hold before we make the call: TLS only, a host we
  // have a connector contract with, and an address outside our own network.
  // Redirects are not followed either, so an approved host cannot bounce the
  // importer somewhere else.
  if (parsed.protocol !== 'https:') ctx.throw(400, 'connector sources must be https');
  if (!APPROVED_HOSTS.has(parsed.hostname.toLowerCase())) {
    ctx.throw(400, 'that host is not an approved connector');
  }

  const resolved = await dns.lookup(parsed.hostname, { all: true });
  if (resolved.length === 0 || resolved.some((entry) => isPrivateAddress(entry.address))) {
    ctx.throw(502, 'connector host resolves to an address inside our network');
  }

  const job = await ImportJob.create({
    requestedBy: ctx.state.user.id,
    sourceUrl: parsed.toString(),
    sourceHost: parsed.hostname,
    state: 'fetching',
  });

  const response = await fetch(parsed.toString(), {
    redirect: 'manual',
    headers: { 'user-agent': 'media-library-connector/2.4', accept: '*/*' },
    signal: AbortSignal.timeout(config.imports.timeoutMs),
  });

  if (response.status >= 300 && response.status < 400) {
    await ImportJob.updateOne(
      { _id: job._id },
      { $set: { state: 'failed', error: 'connector redirected off the approved host' } },
    );
    ctx.throw(502, 'connector redirected off the approved host');
  }
  if (!response.ok) {
    await ImportJob.updateOne(
      { _id: job._id },
      { $set: { state: 'failed', error: `connector responded ${response.status}` } },
    );
    ctx.throw(502, 'the connector could not serve that object');
  }

  const payload = Buffer.from(await response.arrayBuffer());
  if (payload.byteLength > config.imports.maxBytes) {
    ctx.throw(413, 'that object is larger than the import limit');
  }

  const filename = path.posix.basename(parsed.pathname || '') || 'connector.bin';
  const storageKey = storage.newStorageKey(filename);
  const scratch = path.join(os.tmpdir(), `connector-pull-${job.id}`);
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
    sourceHost: parsed.hostname,
  };
});

// GET /api/connectors - which partners we can pull from at all
router.get('/', requireUser, async (ctx) => {
  ctx.body = { connectors: [...APPROVED_HOSTS].map((host) => ({ host, protocol: 'https' })) };
});

module.exports = router;
