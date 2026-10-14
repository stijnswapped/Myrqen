'use strict';

const http = require('node:http');

const clicks = require('../repositories/clicks');

const PORT = Number(process.env.LINK_TRACKER_PORT || 8140);

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(payload));
}

// GET /r?c=<campaign>&to=<destination>
// Newsletter links point here so a click is counted before the reader lands on
// the article. The destination travels in the link itself.
async function followLink(request, response, url) {
  const campaign = url.searchParams.get('c') || 'unknown';
  const destination = url.searchParams.get('to');
  if (!destination) {
    respond(response, 400, { error: 'missing destination' });
    return;
  }

  await clicks.record({ campaign, destination, at: new Date() });

  response.writeHead(302, { Location: destination, 'cache-control': 'no-store' });
  response.end();
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  if (request.method !== 'GET' || url.pathname !== '/r') {
    respond(response, 404, { error: 'not found' });
    return;
  }

  try {
    await followLink(request, response, url);
  } catch (error) {
    console.error('link tracking failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server };
