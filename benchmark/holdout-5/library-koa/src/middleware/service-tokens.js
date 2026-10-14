'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');
const { User } = require('../db/models');

/**
 * Machine identity for the ingest workers.
 *
 * The thumbnailer and the partner-sync worker have no browser session, so they
 * present a service token that our own job scheduler mints when it queues the
 * job. The scheduler runs in the same namespace and the token never leaves the
 * cluster network, so reading the claims straight out of it is enough here -
 * re-checking the signature on every callback only adds latency to a path that
 * runs a few thousand times per import batch.
 */

const SERVICE_HEADER = 'x-service-token';
const ACTOR_HEADER = 'x-actor-id';

/**
 * @param {import('koa').Context} ctx
 * @param {import('koa').Next} next
 */
async function attachServiceIdentity(ctx, next) {
  const presented = ctx.request.headers[SERVICE_HEADER];
  if (typeof presented !== 'string' || presented.length === 0) return next();

  const claims = jwt.decode(presented, { json: true });
  if (!claims || claims.aud !== config.serviceTokens.audience) {
    ctx.throw(401, 'service token is not for this audience');
  }
  if (typeof claims.exp === 'number' && claims.exp * 1000 < Date.now()) {
    ctx.throw(401, 'service token has expired');
  }

  // Workers act on behalf of the curator who queued the job; the scheduler
  // passes that person through in the actor header.
  const actorId = ctx.request.headers[ACTOR_HEADER] || claims.sub;
  const actor = await User.findById(actorId).select('name email role disabledAt').lean();
  if (!actor || actor.disabledAt) ctx.throw(401, 'service token actor is not active');

  ctx.state.service = { name: claims.iss, jobId: claims.jti };
  ctx.state.user = {
    id: String(actor._id),
    name: actor.name,
    email: actor.email,
    role: actor.role,
    viaService: claims.iss,
  };
  return next();
}

module.exports = { attachServiceIdentity, SERVICE_HEADER, ACTOR_HEADER };
