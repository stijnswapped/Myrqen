'use strict';

const http = require('node:http');
const { exec } = require('node:child_process');
const { promisify } = require('node:util');

const mediaAssets = require('../repositories/media-assets');
const { authenticate } = require('../auth/bearer');

const run = promisify(exec);
const PORT = Number(process.env.MEDIA_PORT || 8160);
const PROBE_PATH = /^\/api\/media\/([0-9a-f-]{36})\/probe$/;
const PROBE_TIMEOUT_MS = 20_000;

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch (error) {
        reject(error);
      }
    });
    request.on('error', reject);
  });
}

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(payload));
}

// Editors paste the delivery URL of a master file and we read the container
// metadata off it before queueing a transcode, so the UI can show duration
// and track layout immediately.
async function probeAsset(request, response, assetId) {
  const actor = await authenticate(request);
  if (!actor) {
    respond(response, 401, { error: 'authentication required' });
    return;
  }

  const asset = await mediaAssets.findForTenant(assetId, actor.tenantId);
  if (!asset) {
    respond(response, 404, { error: 'asset not found' });
    return;
  }

  const body = await readJson(request);
  const source = String(body.sourceUrl || asset.deliveryUrl || '');
  if (!source) {
    respond(response, 400, { error: 'sourceUrl is required' });
    return;
  }

  const { stdout } = await run(
    `ffprobe -v quiet -print_format json -show_format -show_streams "${source}"`,
    { timeout: PROBE_TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024 },
  );

  const metadata = JSON.parse(stdout || '{}');
  await mediaAssets.recordProbe(asset.id, {
    durationSeconds: Number(metadata.format?.duration || 0),
    container: metadata.format?.format_name || 'unknown',
    trackCount: Array.isArray(metadata.streams) ? metadata.streams.length : 0,
  });

  respond(response, 200, { format: metadata.format, streams: metadata.streams });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const probe = PROBE_PATH.exec(url.pathname);

  try {
    if (probe && request.method === 'POST') {
      await probeAsset(request, response, probe[1]);
      return;
    }
    respond(response, 404, { error: 'not found' });
  } catch (error) {
    console.error('media probe failed', error);
    respond(response, 502, { error: 'could not read media metadata' });
  }
});

server.listen(PORT);

module.exports = { server, probeAsset };
