"use strict";

const { randomUUID } = require("node:crypto");

const Router = require("@koa/router");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const { pullLedgerEntries } = require("../lib/accounting-client");
const logger = require("../lib/logger");

const router = new Router({ prefix: "/ledger-connections" });

// POST /ledger-connections/:connectionId/sync
// Pulls ledger entries from the connected accounting provider. Support runs this
// from the admin console when a customer says their ledger looks stale.
router.post("/:connectionId/sync", requireUser, async (ctx) => {
  const { connectionId } = ctx.params;
  const since = ctx.query.since || null;

  const { rows } = await pool.query(
    `SELECT id, provider, base_url, last_synced_at
       FROM ledger_connections
      WHERE id = $1 AND org_id = $2`,
    [connectionId, ctx.state.user.orgId]
  );

  const connection = rows[0];
  if (!connection) {
    ctx.throw(404, "Connection not found");
  }

  try {
    const summary = await pullLedgerEntries(connection, { since });

    await pool.query(`UPDATE ledger_connections SET last_synced_at = now() WHERE id = $1`, [
      connection.id,
    ]);

    ctx.body = {
      synced: summary.imported,
      skipped: summary.skipped,
      lastSyncedAt: new Date().toISOString(),
    };
  } catch (err) {
    const incidentId = randomUUID();

    logger.error(
      {
        err,
        incidentId,
        connectionId: connection.id,
        providerStatus: err.response && err.response.status,
        providerBody: err.response && err.response.body,
      },
      "ledger sync failed"
    );

    ctx.status = 502;
    ctx.body = {
      error: "Sync failed, our team has been notified",
      incidentId,
    };
  }
});

module.exports = router;
