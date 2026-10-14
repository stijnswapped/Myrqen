'use strict';

const Koa = require('koa');
const cors = require('@koa/cors');
const helmet = require('koa-helmet');
const bodyParser = require('koa-bodyparser');
const config = require('./config');
const models = require('./db/models');
const { attachSession } = require('./middleware/session');
const { attachServiceIdentity } = require('./middleware/service-tokens');
const assetFiles = require('./routes/asset-files');
const collections = require('./routes/collections');
const playlists = require('./routes/playlists');
const reviewQueue = require('./routes/review-queue');
const commentDigest = require('./routes/comment-digest');
const tagSearch = require('./routes/tag-search');
const imports = require('./routes/imports');
const connectorSync = require('./routes/connector-sync');

const app = new Koa();
app.proxy = true;

/** Single place that turns thrown errors into a response body. */
app.use(async (ctx, next) => {
  const startedAt = Date.now();
  try {
    await next();
  } catch (error) {
    const status = Number.isInteger(error.status) ? error.status : 500;
    ctx.status = status;
    ctx.body = { error: status < 500 || error.expose ? error.message : 'internal error' };
    if (status >= 500) {
      console.error('[media-library] request failed', {
        method: ctx.method,
        path: ctx.path,
        message: error.message,
      });
    }
  } finally {
    ctx.set('x-response-time', `${Date.now() - startedAt}ms`);
  }
});

app.use(helmet());
app.use(cors({ origin: config.web.origin, credentials: true }));
app.use(bodyParser({ enableTypes: ['json', 'form'], jsonLimit: '1mb' }));

// Browser sessions first, then the machine identity the ingest workers use.
app.use(attachSession);
app.use(attachServiceIdentity);

const routers = [
  assetFiles,
  collections,
  playlists,
  reviewQueue,
  commentDigest,
  tagSearch,
  imports,
  connectorSync,
];

for (const router of routers) {
  app.use(router.routes());
  app.use(router.allowedMethods());
}

async function start() {
  await models.connect();
  return app.listen(config.port, () => {
    console.log(`media library api listening on :${config.port}`);
  });
}

if (require.main === module) {
  start().catch((error) => {
    console.error('[media-library] failed to start', error);
    process.exit(1);
  });
}

module.exports = { app, start };
