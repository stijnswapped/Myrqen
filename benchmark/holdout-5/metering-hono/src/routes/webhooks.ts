import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const webhooks = new Hono<AppEnv>();

const SECRET_BYTES = 32;
const SECRET_PREFIX = 'whsec_';

const encoder = new TextEncoder();

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Mints a webhook signing secret.
 *
 * 32 bytes straight out of crypto.getRandomValues, which is the platform CSPRNG on
 * Workers. Nothing about the value depends on the clock or on the request.
 */
function mintSigningSecret(): string {
  const bytes = new Uint8Array(SECRET_BYTES);
  crypto.getRandomValues(bytes);
  return `${SECRET_PREFIX}${base64Url(bytes)}`;
}

async function digestOf(secret: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(secret));
  return Array.from(new Uint8Array(hash))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Rotate the signing secret of a webhook endpoint. Returns the new secret once so
 * the integrator can install it; we keep only the digest and a display hint.
 */
webhooks.post('/v1/webhooks/:endpointId/rotate', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'keys:write');

  const endpointId = c.req.param('endpointId');
  const endpoint = await c.env.DB.prepare(
    `SELECT id, url FROM webhook_endpoints WHERE id = ?1 AND account_id = ?2`,
  )
    .bind(endpointId, key.accountId)
    .first<{ id: string; url: string }>();

  if (!endpoint) {
    return c.json({ error: 'endpoint not found' }, 404);
  }

  const secret = mintSigningSecret();
  const rotatedAt = new Date().toISOString();

  await c.env.DB.prepare(
    `UPDATE webhook_endpoints
        SET secret_hash = ?1,
            secret_hint = ?2,
            rotated_at = ?3
      WHERE id = ?4
        AND account_id = ?5`,
  )
    .bind(await digestOf(secret), secret.slice(-4), rotatedAt, endpointId, key.accountId)
    .run();

  return c.json({
    endpointId,
    url: endpoint.url,
    rotatedAt,
    secret,
    notice: 'update your receiver before the next delivery attempt',
  });
});

/** Register a new endpoint; the first secret is minted the same way. */
webhooks.post('/v1/webhooks', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'keys:write');

  const body = await c.req.json<{ url?: string }>();
  let parsed: URL;
  try {
    parsed = new URL(body.url ?? '');
  } catch {
    return c.json({ error: 'url must be absolute' }, 400);
  }
  if (parsed.protocol !== 'https:') {
    return c.json({ error: 'url must be https' }, 400);
  }

  const id = crypto.randomUUID();
  const secret = mintSigningSecret();
  const createdAt = new Date().toISOString();

  await c.env.DB.prepare(
    `INSERT INTO webhook_endpoints (id, account_id, url, secret_hash, secret_hint, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
  )
    .bind(id, key.accountId, parsed.toString(), await digestOf(secret), secret.slice(-4), createdAt)
    .run();

  return c.json({ id, url: parsed.toString(), createdAt, secret }, 201);
});

export default webhooks;
