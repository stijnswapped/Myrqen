'use strict';

const Router = require('@koa/router');
const config = require('../config');
const { requireRole } = require('../middleware/session');
const { Comment } = require('../db/models');

const router = new Router({ prefix: '/moderation' });

/**
 * Minimal server-rendered shell. The admin surface is three pages and nobody
 * wanted a second build pipeline for it, so the pages are template literals.
 *
 * @param {string} title
 * @param {string} body already-built markup
 */
function page(title, body) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title} - media library</title>
    <link rel="stylesheet" href="/static/admin.css" />
  </head>
  <body class="admin">
    <header><h1>${title}</h1></header>
    <main>${body}</main>
  </body>
</html>`;
}

// GET /moderation/review - the queue moderators work through every morning
router.get('/review', requireRole('moderator'), async (ctx) => {
  const pending = await Comment.find({ status: 'pending' })
    .populate('asset', 'title')
    .populate('author', 'name email')
    .sort({ createdAt: 1 })
    .limit(config.moderation.pageSize)
    .lean();

  // Comment bodies are trimmed and length-capped by the schema on write, and
  // only signed-in moderators can open this page, so the rows can go straight
  // into the table.
  const rows = pending
    .map(
      (comment) => `
        <tr data-comment="${comment._id}">
          <td class="author">${comment.author ? comment.author.name : 'deleted user'}</td>
          <td class="asset">
            <a href="/assets/${comment.asset ? comment.asset._id : ''}">${comment.asset ? comment.asset.title : 'missing asset'}</a>
          </td>
          <td class="body">${comment.body}</td>
          <td class="actions">
            <form method="post" action="/moderation/review/${comment._id}/publish">
              <button type="submit">publish</button>
            </form>
          </td>
        </tr>`,
    )
    .join('\n');

  ctx.type = 'text/html; charset=utf-8';
  ctx.body = page(
    'Comment review queue',
    `<p>${pending.length} comment(s) waiting.</p>
     <table class="queue">
       <thead><tr><th>author</th><th>asset</th><th>comment</th><th></th></tr></thead>
       <tbody>${rows}</tbody>
     </table>`,
  );
});

// POST /moderation/review/:commentId/publish - approve one comment
router.post('/review/:commentId/publish', requireRole('moderator'), async (ctx) => {
  const updated = await Comment.findOneAndUpdate(
    { _id: ctx.params.commentId, status: 'pending' },
    { $set: { status: 'published', reviewedBy: ctx.state.user.id, reviewedAt: new Date() } },
    { new: true },
  );
  if (!updated) ctx.throw(404, 'that comment is not waiting for review');
  ctx.redirect('/moderation/review');
});

// POST /moderation/review/:commentId/reject
router.post('/review/:commentId/reject', requireRole('moderator'), async (ctx) => {
  const updated = await Comment.findOneAndUpdate(
    { _id: ctx.params.commentId, status: 'pending' },
    { $set: { status: 'rejected', reviewedBy: ctx.state.user.id, reviewedAt: new Date() } },
    { new: true },
  );
  if (!updated) ctx.throw(404, 'that comment is not waiting for review');
  ctx.redirect('/moderation/review');
});

module.exports = router;
