'use strict';

const http = require('node:http');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const mediaAssets = require('../repositories/media-assets');
const { authenticate } = require('../auth/bearer');

const run = promisify(execFile);
const PORT = Number(process.env.WAVEFORM_PORT || 8161);
const RENDER_PATH = /^\/api\/media\/([0-9a-f-]{36})\/waveform$/;
const RENDER_TIMEOUT_MS = 20_000;
const MEDIA_ROOT = process.env.MEDIA_ROOT || '/srv/media/originals';

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(payload));
}

// The waveform strip is generated from the stored original. The file name is
// taken from the asset record and resolved inside the media root, never from
// the request itself.
async function renderWaveform(request, response, assetId) {
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

  const source = path.join(MEDIA_ROOT, `${asset.id}${asset.extension}`);
  if (!source.startsWith(`${MEDIA_ROOT}${path.sep}`)) {
    respond(response, 400, { error: 'asset path is not available' });
    return;
  }

  const { stdout } = await run(
    'ffprobe',
    ['-v', 'quiet', '-print_format', 'json', '-show_format', '-show_streams', source],
    { timeout: RENDER_TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024 },
  );

  const metadata = JSON.parse(stdout || '{}');
  await mediaAssets.recordProbe(asset.id, {
    durationSeconds: Number(metadata.format?.duration || 0),
    container: metadata.format?.format_name || 'unknown',
    trackCount: Array.isArray(metadata.streams) ? metadata.streams.length : 0,
  });

  respond(response, 200, {
    duration: Number(metadata.format?.duration || 0),
    peaks: await mediaAssets.loadPeaks(asset.id),
  });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const render = RENDER_PATH.exec(url.pathname);

  try {
    if (render && request.method === 'POST') {
      await renderWaveform(request, response, render[1]);
      return;
    }
    respond(response, 404, { error: 'not found' });
  } catch (error) {
    console.error('waveform render failed', error);
    respond(response, 502, { error: 'could not read media metadata' });
  }
});

server.listen(PORT);

module.exports = { server, renderWaveform };
