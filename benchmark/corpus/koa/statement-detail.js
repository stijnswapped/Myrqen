"use strict";

const Router = require("@koa/router");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const { signDownloadUrl } = require("../lib/storage");

const router = new Router({ prefix: "/statements" });

const DOWNLOAD_TTL_SECONDS = 300;

// GET /statements
// The monthly statement list, newest first.
router.get("/", requireUser, async (ctx) => {
  const { rows } = await pool.query(
    `SELECT id, period, status, total_cents, created_at
       FROM statements
      WHERE org_id = $1
      ORDER BY period DESC
      LIMIT 50`,
    [ctx.state.user.orgId]
  );

  ctx.body = { statements: rows };
});

// GET /statements/:statementId
// Detail panel for one statement, including a short-lived download link once the
// worker has finished writing the PDF.
router.get("/:statementId", requireUser, async (ctx) => {
  const { statementId } = ctx.params;

  const { rows } = await pool.query(
    `SELECT id, period, status, total_cents, storage_key, requested_by, org_id, created_at
       FROM statements
      WHERE id = $1 AND org_id = $2`,
    [statementId, ctx.state.user.orgId]
  );

  const record = rows[0];
  if (!record) {
    ctx.throw(404, "Statement not found");
  }

  ctx.body = {
    statement: {
      id: record.id,
      period: record.period,
      status: record.status,
      totalCents: record.total_cents,
      requestedBy: record.requested_by,
      createdAt: record.created_at,
    },
    downloadUrl:
      record.status === "ready"
        ? await signDownloadUrl(record.storage_key, DOWNLOAD_TTL_SECONDS)
        : null,
  };
});

module.exports = router;
