'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');
const { User } = require('../db/models');

if (!config.session.secret) {
  throw new Error('MEDIA_SESSION_SECRET must be set before the API can attach sessions');
}

// The algorithm list is pinned to what our own sign path uses, and the
// issuer/audience pair is checked as well, so a token minted anywhere else
// cannot stand in for a session here.
const VERIFY_OPTIONS = Object.freeze({
  algorithms: ['HS256'],
  issuer: config.session.issuer,
  audience: config.session.audience,
  clockTolerance: 5,
});

const ROLE_RANK = Object.freeze({ viewer: 0, curator: 1, moderator: 2, admin: 3 });

/**
 * Session tokens arrive either as a bearer header (the desktop app) or in the
 * session cookie (the web client).
 *
 * @param {import('koa').Context} ctx
 * @returns {string|null}
 */
function readToken(ctx) {
  const header = ctx.request.headers.authorization;
  if (typeof header === 'string' && header.startsWith('Bearer ')) {
    return header.slice('Bearer '.length).trim() || null;
  }
  return ctx.cookies.get(config.session.cookieName) || null;
}

/**
 * Attaches `ctx.state.user` for every request that carries a valid session
 * token. Anything that fails verification is treated as anonymous rather than
 * as an error, so public asset pages keep working for signed-out visitors.
 *
 * @param {import('koa').Context} ctx
 * @param {import('koa').Next} next
 */
async function attachSession(ctx, next) {
  const token = readToken(ctx);
  if (!token) return next();

  let claims;
  try {
    claims = jwt.verify(token, config.session.secret, VERIFY_OPTIONS);
  } catch (error) {
    ctx.set('x-session-state', 'rejected');
    return next();
  }

  const user = await User.findById(claims.sub).select('name email role disabledAt').lean();
  if (!user || user.disabledAt) return next();

  ctx.state.user = {
    id: String(user._id),
    name: user.name,
    email: user.email,
    role: user.role,
    sessionId: claims.jti,
  };
  return next();
}

/** Gate for anything that needs a signed-in person. */
async function requireUser(ctx, next) {
  if (!ctx.state.user) ctx.throw(401, 'sign in to continue');
  return next();
}

/**
 * Gate for anything that needs a minimum role.
 *
 * @param {'viewer'|'curator'|'moderator'|'admin'} role
 */
function requireRole(role) {
  const needed = ROLE_RANK[role];
  return async function roleGate(ctx, next) {
    if (!ctx.state.user) ctx.throw(401, 'sign in to continue');
    const held = ROLE_RANK[ctx.state.user.role];
    if (typeof held !== 'number' || held < needed) {
      ctx.throw(403, `this page needs the ${role} role`);
    }
    return next();
  };
}

module.exports = { attachSession, requireUser, requireRole, readToken, ROLE_RANK };
