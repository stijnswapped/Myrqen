'use strict';

const Router = require('@koa/router');
const config = require('../config');
const { requireRole } = require('../middleware/session');
const { Comment } = require('../db/models');

const router = new Router({ prefix: '/moderation' });

const ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/**
 * Every value that reaches the digest markup goes through here first. Comment
 * bodies are written by anybody who can see an asset, so the digest treats them
 * as text and never as markup.
 *
 * @param {unknown} value
 * @returns {string}
 */
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (character) => ENTITIES[character]);
}

/**
 * @param {string} title
 * @param {string} body already-escaped markup
 */
function page(title, body) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)} - media library</title>
    <link rel="stylesheet" href="/static/admin.css" />
  </head>
  <body class="admin">
    <header><h1>${escapeHtml(title)}</h1></header>
    <main>${body}</main>
  </body>
</html>`;
}

// GET /moderation/digest - what was published in the last 24 hours, for the
// morning stand-up screen in the newsroom
router.get('/digest', requireRole('moderator'), async (ctx) => {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const published = await Comment.find({ status: 'published', reviewedAt: { $gte: since } })
    .populate('asset', 'title')
    .populate('author', 'name')
    .sort({ reviewedAt: -1 })
    .limit(config.moderation.pageSize)
    .lean();

  const rows = published
    .map(
      (comment) => `
        <tr data-comment="${escapeHtml(comment._id)}">
          <td class="author">${escapeHtml(comment.author ? comment.author.name : 'deleted user')}</td>
          <td class="asset">
            <a href="/assets/${encodeURIComponent(String(comment.asset ? comment.asset._id : ''))}">${escapeHtml(comment.asset ? comment.asset.title : 'missing asset')}</a>
          </td>
          <td class="body">${escapeHtml(comment.body)}</td>
          <td class="reviewed">${escapeHtml(comment.reviewedAt && comment.reviewedAt.toISOString())}</td>
        </tr>`,
    )
    .join('\n');

  ctx.type = 'text/html; charset=utf-8';
  ctx.set('content-security-policy', "default-src 'none'; style-src 'self'");
  ctx.body = page(
    'Published in the last day',
    `<p>${published.length} comment(s) published.</p>
     <table class="digest">
       <thead><tr><th>author</th><th>asset</th><th>comment</th><th>reviewed</th></tr></thead>
       <tbody>${rows}</tbody>
     </table>`,
  );
});

// GET /moderation/digest.json - same window, for the Slack poster
router.get('/digest.json', requireRole('moderator'), async (ctx) => {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const published = await Comment.find({ status: 'published', reviewedAt: { $gte: since } })
    .populate('asset', 'title')
    .populate('author', 'name')
    .limit(config.moderation.pageSize)
    .lean();

  ctx.body = {
    since,
    comments: published.map((comment) => ({
      id: comment._id,
      author: comment.author ? comment.author.name : null,
      asset: comment.asset ? comment.asset.title : null,
      body: comment.body,
    })),
  };
});

module.exports = router;
