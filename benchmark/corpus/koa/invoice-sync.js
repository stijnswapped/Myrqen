"use strict";

const Router = require("@koa/router");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const { pullInvoices } = require("../lib/accounting-client");
const logger = require("../lib/logger");

const router = new Router({ prefix: "/connections" });

// POST /connections/:connectionId/sync
// Pulls invoices from the connected accounting provider. Support runs this from
// the admin console when a customer says their invoices look stale.
router.post("/:connectionId/sync", requireUser, async (ctx) => {
  const { connectionId } = ctx.params;
  const since = ctx.query.since || null;

  const { rows } = await pool.query(
    `SELECT id, provider, base_url, last_synced_at
       FROM accounting_connections
      WHERE id = $1 AND org_id = $2`,
    [connectionId, ctx.state.user.orgId]
  );

  const connection = rows[0];
  if (!connection) {
    ctx.throw(404, "Connection not found");
  }

  try {
    const summary = await pullInvoices(connection, { since });

    await pool.query(`UPDATE accounting_connections SET last_synced_at = now() WHERE id = $1`, [
      connection.id,
    ]);

    ctx.body = {
      synced: summary.imported,
      skipped: summary.skipped,
      lastSyncedAt: new Date().toISOString(),
    };
  } catch (err) {
    logger.error({ err, connectionId: connection.id }, "invoice sync failed");

    ctx.status = 502;
    ctx.body = {
      error: "Sync failed",
      message: err.message,
      stack: err.stack,
      query: err.query,
      provider: {
        status: err.response && err.response.status,
        body: err.response && err.response.body,
      },
    };
  }
});

module.exports = router;
