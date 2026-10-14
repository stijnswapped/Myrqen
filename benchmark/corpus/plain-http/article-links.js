'use strict';

const http = require('node:http');

const clicks = require('../repositories/clicks');
const articles = require('../repositories/articles');

const PORT = Number(process.env.ARTICLE_LINKS_PORT || 8141);
const ARTICLE_ID = /^[0-9a-z-]{4,80}$/;

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(payload));
}

// GET /a?c=<campaign>&id=<article>
// Newsletter links point here so a click is counted before the reader lands on
// the article. The link carries the article id; the address is ours.
async function followArticle(request, response, url) {
  const campaign = url.searchParams.get('c') || 'unknown';
  const id = url.searchParams.get('id') || '';
  if (!ARTICLE_ID.test(id) || !(await articles.exists(id))) {
    respond(response, 404, { error: 'unknown article' });
    return;
  }

  await clicks.record({ campaign, article: id, at: new Date() });

  response.writeHead(302, { Location: '/articles/' + encodeURIComponent(id), 'cache-control': 'no-store' });
  response.end();
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  if (request.method !== 'GET' || url.pathname !== '/a') {
    respond(response, 404, { error: 'not found' });
    return;
  }

  try {
    await followArticle(request, response, url);
  } catch (error) {
    console.error('article link failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server };
