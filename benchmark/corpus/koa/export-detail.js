"use strict";

const Router = require("@koa/router");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const { signDownloadUrl } = require("../lib/storage");

const router = new Router({ prefix: "/exports" });

const DOWNLOAD_TTL_SECONDS = 300;

// GET /exports
// The export history table, newest first.
router.get("/", requireUser, async (ctx) => {
  const { rows } = await pool.query(
    `SELECT id, kind, status, row_count, created_at
       FROM exports
      WHERE org_id = $1
      ORDER BY created_at DESC
      LIMIT 50`,
    [ctx.state.user.orgId]
  );

  ctx.body = { exports: rows };
});

// GET /exports/:exportId
// Detail panel for one export, including a short-lived download link once the
// worker has finished writing the file.
router.get("/:exportId", requireUser, async (ctx) => {
  const { exportId } = ctx.params;

  const { rows } = await pool.query(
    `SELECT id, kind, status, row_count, storage_key, requested_by, org_id, created_at
       FROM exports
      WHERE id = $1`,
    [exportId]
  );

  const record = rows[0];
  if (!record) {
    ctx.throw(404, "Export not found");
  }

  ctx.body = {
    export: {
      id: record.id,
      kind: record.kind,
      status: record.status,
      rowCount: record.row_count,
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
