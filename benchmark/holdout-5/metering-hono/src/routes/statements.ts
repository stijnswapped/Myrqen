import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { PERIOD_PATTERN } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const statements = new Hono<AppEnv>();

const STATEMENT_ROOT = 'statements';
/** Statement files are named by us: <customer external ref>-<period>.pdf */
const FILE_NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}\.pdf$/;

/**
 * Download a monthly statement by period and file name.
 *
 * The two request-supplied segments are checked against fixed patterns before they
 * are joined onto the prefix: the period must be YYYY-MM and the file name may only
 * contain lower-case letters, digits, dash and underscore followed by .pdf. Neither
 * can contain a slash, a dot pair or an encoded separator, so the composed key stays
 * inside statements/<accountId>/.
 */
statements.get('/v1/statements/:period/:fileName', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'exports:read');

  const period = c.req.param('period');
  const fileName = c.req.param('fileName');

  if (!PERIOD_PATTERN.test(period) || !FILE_NAME_PATTERN.test(fileName)) {
    return c.json({ error: 'unknown statement' }, 400);
  }

  const objectKey = `${STATEMENT_ROOT}/${key.accountId}/${period}/${fileName}`;
  const object = await c.env.EXPORTS.get(objectKey);
  if (!object) {
    return c.json({ error: 'statement not found' }, 404);
  }

  return new Response(object.body, {
    headers: {
      'content-type': 'application/pdf',
      'content-disposition': `attachment; filename="${fileName}"`,
      'cache-control': 'private, no-store',
    },
  });
});

/**
 * Download a statement by its id. The object key is not taken from the request at
 * all here: it comes out of the row, and the row is selected with the account id
 * from the resolved key, so an id from another tenant yields a 404.
 */
statements.get('/v1/statements/:statementId', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'exports:read');

  const row = await c.env.DB.prepare(
    `SELECT object_key, period, status
       FROM statements
      WHERE id = ?1
        AND account_id = ?2`,
  )
    .bind(c.req.param('statementId'), key.accountId)
    .first<{ object_key: string; period: string; status: string }>();

  if (!row || row.status !== 'ready') {
    return c.json({ error: 'statement not found' }, 404);
  }

  const object = await c.env.EXPORTS.get(row.object_key);
  if (!object) {
    return c.json({ error: 'statement expired' }, 410);
  }

  return new Response(object.body, {
    headers: {
      'content-type': object.httpMetadata?.contentType ?? 'application/pdf',
      'content-disposition': `attachment; filename="statement-${row.period}.pdf"`,
      'cache-control': 'private, no-store',
    },
  });
});

export default statements;
