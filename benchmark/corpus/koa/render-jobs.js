"use strict";

const { exec } = require("node:child_process");
const path = require("node:path");
const { promisify } = require("node:util");

const Router = require("@koa/router");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const run = promisify(exec);

const router = new Router({ prefix: "/render-jobs" });

const OUTPUT_DIR = process.env.RENDER_OUTPUT_DIR || "/var/lib/reporting/renders";
const RENDER_BASE = process.env.RENDER_BASE_URL || "http://localhost:4000";

// POST /render-jobs
// Queues a PDF render of one dashboard. The caller names the output file so the
// finance team can find it on the shared drive afterwards.
router.post("/", requireUser, async (ctx) => {
  const { dashboardId, filename, pageSize } = ctx.request.body || {};

  if (!dashboardId || !filename) {
    ctx.throw(400, "dashboardId and filename are required");
  }

  const { rows } = await pool.query(
    `SELECT id, slug, title
       FROM dashboards
      WHERE id = $1 AND org_id = $2`,
    [dashboardId, ctx.state.user.orgId]
  );

  const dashboard = rows[0];
  if (!dashboard) {
    ctx.throw(404, "Dashboard not found");
  }

  const target = path.join(OUTPUT_DIR, `${filename}.pdf`);
  const size = pageSize === "Letter" ? "Letter" : "A4";

  const started = Date.now();
  await run(
    `wkhtmltopdf --page-size ${size} --quiet ${RENDER_BASE}/dashboards/${dashboard.slug} "${target}"`,
    { timeout: 60_000 }
  );

  const inserted = await pool.query(
    `INSERT INTO render_jobs (org_id, dashboard_id, requested_by, output_path, duration_ms)
          VALUES ($1, $2, $3, $4, $5)
       RETURNING id, output_path, created_at`,
    [ctx.state.user.orgId, dashboard.id, ctx.state.user.id, target, Date.now() - started]
  );

  logger.info({ jobId: inserted.rows[0].id, dashboardId: dashboard.id }, "render complete");

  ctx.status = 201;
  ctx.body = { job: inserted.rows[0] };
});

module.exports = router;
