import type { Context, MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import type { ApiKeyRecord, AppEnv } from '../bindings';

const encoder = new TextEncoder();

interface ApiKeyRow {
  id: string;
  account_id: string;
  label: string;
  prefix: string;
  scopes: string;
}

/**
 * SHA-256 of the presented secret. Only the digest is stored in `api_keys.key_hash`,
 * so a database dump does not hand out working credentials.
 */
async function digestOf(secret: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(secret));
  return Array.from(new Uint8Array(hash))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function presentedSecret(c: Context<AppEnv>): string | null {
  const authorization = c.req.header('authorization');
  if (authorization && authorization.toLowerCase().startsWith('bearer ')) {
    return authorization.slice('bearer '.length).trim();
  }
  const headerKey = c.req.header('x-api-key');
  return headerKey ? headerKey.trim() : null;
}

/**
 * Resolves the caller's API key for every `/v1/*` request.
 *
 * The key itself never leaves this function: we hash it, look the digest up in D1,
 * and put only the row (id, account, scopes) on the context. Request logs downstream
 * therefore cannot contain a usable credential.
 */
export const apiKeyAuth = (): MiddlewareHandler<AppEnv> => async (c, next) => {
  const presented = presentedSecret(c);
  if (!presented || presented.length < 24) {
    throw new HTTPException(401, { message: 'api key required' });
  }

  const row = await c.env.DB.prepare(
    `SELECT id, account_id, label, prefix, scopes
       FROM api_keys
      WHERE key_hash = ?1
        AND revoked_at IS NULL`,
  )
    .bind(await digestOf(presented))
    .first<ApiKeyRow>();

  if (!row) {
    throw new HTTPException(401, { message: 'api key not recognised' });
  }

  c.set('apiKey', {
    id: row.id,
    accountId: row.account_id,
    label: row.label,
    prefix: row.prefix,
    scopes: row.scopes ? row.scopes.split(' ') : [],
  });

  c.executionCtx.waitUntil(
    c.env.DB.prepare(`UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2`)
      .bind(new Date().toISOString(), row.id)
      .run(),
  );

  await next();
};

/**
 * Gate for platform-internal callers on `/internal/*` (billing runner, ops jobs).
 *
 * Two things do the work here. The shared secret is compared with
 * crypto.subtle.timingSafeEqual after a length check, so neither the value nor its
 * length leaks through response timing. The peer address comes from CF-Connecting-IP,
 * which the edge overwrites on every request, so a client cannot claim to be one of
 * the runner hosts by setting a header.
 */
export const internalServiceAuth = (): MiddlewareHandler<AppEnv> => async (c, next) => {
  const presented = encoder.encode(c.req.header('x-internal-secret') ?? '');
  const expected = encoder.encode(c.env.INTERNAL_SERVICE_SECRET);

  if (expected.byteLength === 0) {
    throw new HTTPException(500, { message: 'internal secret not configured' });
  }
  if (presented.byteLength !== expected.byteLength || !crypto.subtle.timingSafeEqual(presented, expected)) {
    throw new HTTPException(403, { message: 'internal caller not authorised' });
  }

  const peer = c.req.raw.headers.get('cf-connecting-ip') ?? '';
  const allowed = c.env.INTERNAL_ALLOWED_IPS.split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (allowed.length > 0 && !allowed.includes(peer)) {
    throw new HTTPException(403, { message: 'internal caller not authorised' });
  }

  c.set('internalService', c.req.header('x-internal-service') ?? 'unnamed');
  await next();
};

/** Handler-side accessor so a route can never accidentally run unauthenticated. */
export function requireApiKey(c: Context<AppEnv>): ApiKeyRecord {
  const key = c.get('apiKey');
  if (!key) {
    throw new HTTPException(401, { message: 'api key required' });
  }
  return key;
}

export function requireScope(key: ApiKeyRecord, scope: string): void {
  if (!key.scopes.includes(scope) && !key.scopes.includes('*')) {
    throw new HTTPException(403, { message: `scope ${scope} required` });
  }
}
