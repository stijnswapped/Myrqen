import { Hono } from "hono";

import { db } from "../lib/db";
import { requireSession } from "../middleware/session";
import type { SessionEnv } from "../lib/env";

const reports = new Hono<SessionEnv>();

reports.use("*", requireSession);

function readLimit(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 25;
  }
  return Math.min(parsed, 100);
}

// GET /reports
// The saved-reports list on the analytics landing page.
reports.get("/reports", async (c) => {
  const viewer = c.get("viewer");

  const rows = await db.report.findMany({
    where: { workspaceId: viewer.workspaceId, archivedAt: null },
    orderBy: { generatedAt: "desc" },
    take: readLimit(c.req.query("limit")),
    select: { id: true, title: true, generatedAt: true, ownerId: true },
  });

  return c.json({ reports: rows });
});

// GET /reports/:id
// Detail view: the report header, its rendered series, and the people who
// currently have it shared with them.
reports.get("/reports/:id", async (c) => {
  const viewer = c.get("viewer");
  const id = c.req.param("id");

  const report = await db.report.findFirst({
    where: { id, workspaceId: viewer.workspaceId },
    select: {
      id: true,
      title: true,
      series: true,
      workspaceId: true,
      ownerId: true,
      generatedAt: true,
    },
  });

  if (!report) {
    return c.json({ error: "Report not found" }, 404);
  }

  const recipients = await db.reportShare.findMany({
    where: { reportId: report.id },
    orderBy: { displayName: "asc" },
    select: { userId: true, displayName: true, role: true },
  });

  return c.json({ report, recipients });
});

export default reports;
