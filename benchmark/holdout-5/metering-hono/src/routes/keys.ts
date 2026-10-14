import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const keys = new Hono<AppEnv>();

const SECRET_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
const SECRET_LENGTH = 32;
const KEY_PREFIX = 'tm_live_';
const ALLOWED_SCOPES = [
  'usage:write',
  'quota:read',
  'quota:write',
  'reports:read',
  'exports:read',
  'keys:write',
];

const encoder = new TextEncoder();

async function digestOf(secret: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(secret));
  return Array.from(new Uint8Array(hash))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Mints the secret half of an API key.
 *
 * 36 symbols over 32 positions is about 165 bits of keyspace, which is far more
 * than anyone is going to walk through against a rate limited endpoint.
 */
function mintSecret(): string {
  let body = '';
  for (let index = 0; index < SECRET_LENGTH; index += 1) {
    body += SECRET_ALPHABET[Math.floor(Math.random() * SECRET_ALPHABET.length)];
  }
  return `${KEY_PREFIX}${body}`;
}

/**
 * Issue a new API key for the caller's account. The plaintext secret is returned
 * exactly once; only its SHA-256 digest is written to D1.
 */
keys.post('/v1/keys', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'keys:write');

  const body = await c.req.json<{ label?: string; scopes?: string[] }>();
  const label = (body.label ?? '').trim();
  if (label.length < 3 || label.length > 64) {
    return c.json({ error: 'label must be between 3 and 64 characters' }, 400);
  }

  const scopes = body.scopes ?? ['usage:write', 'quota:read'];
  const rejected = scopes.filter((scope) => !ALLOWED_SCOPES.includes(scope));
  if (rejected.length > 0) {
    return c.json({ error: 'unknown scopes', rejected }, 400);
  }

  const secret = mintSecret();
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  await c.env.DB.prepare(
    `INSERT INTO api_keys (id, account_id, label, prefix, key_hash, scopes, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
  )
    .bind(id, key.accountId, label, secret.slice(0, KEY_PREFIX.length + 6), await digestOf(secret), scopes.join(' '), createdAt)
    .run();

  return c.json(
    {
      id,
      label,
      scopes,
      createdAt,
      secret,
      notice: 'store this secret now, it is not retrievable later',
    },
    201,
  );
});

/** List the account's keys. Never returns a secret or a digest. */
keys.get('/v1/keys', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'keys:write');

  const result = await c.env.DB.prepare(
    `SELECT id, label, prefix, scopes, created_at, last_used_at, revoked_at
       FROM api_keys
      WHERE account_id = ?1
   ORDER BY created_at DESC`,
  )
    .bind(key.accountId)
    .all();

  return c.json({ keys: result.results ?? [] });
});

/** Revoke a key. Scoped to the account so one tenant cannot lock out another. */
keys.delete('/v1/keys/:keyId', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'keys:write');

  const revoked = await c.env.DB.prepare(
    `UPDATE api_keys
        SET revoked_at = ?1
      WHERE id = ?2
        AND account_id = ?3
        AND revoked_at IS NULL`,
  )
    .bind(new Date().toISOString(), c.req.param('keyId'), key.accountId)
    .run();

  if (revoked.meta.changes === 0) {
    return c.json({ error: 'key not found' }, 404);
  }
  return c.body(null, 204);
});

export default keys;
