import { Hono } from "hono";

import { pool } from "../lib/db";
import { requireSession } from "../middleware/session";
import type { SessionEnv } from "../lib/env";

const conversations = new Hono<SessionEnv>();

const SORT_COLUMNS: Record<string, string> = {
  updated: "updated_at",
  created: "created_at",
  subject: "subject",
};

function readLimit(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 50;
  }
  return Math.min(parsed, 200);
}

// GET /conversations/search
// The agent inbox filter bar: free-text subject match, the priority chips (the
// UI allows more than one), an optional assignee, and the column sort.
conversations.get("/conversations/search", requireSession, async (c) => {
  const viewer = c.get("viewer");
  const subject = c.req.query("subject");
  const assignee = c.req.query("assignee");
  const priorities = c.req.queries("priority") ?? [];
  const sortColumn = SORT_COLUMNS[c.req.query("sort") ?? ""] ?? "updated_at";
  const direction = c.req.query("dir") === "asc" ? "ASC" : "DESC";

  const clauses = ["workspace_id = $1"];
  const values: unknown[] = [viewer.workspaceId];

  if (subject) {
    values.push(`%${subject}%`);
    clauses.push(`subject ILIKE $${values.length}`);
  }

  if (assignee) {
    values.push(assignee);
    clauses.push(`assignee_id = $${values.length}`);
  }

  if (priorities.length > 0) {
    clauses.push(`priority IN (${priorities.map((value) => `'${value}'`).join(", ")})`);
  }

  values.push(readLimit(c.req.query("limit")));

  const sql = `
    SELECT id, subject, priority, assignee_id, updated_at
      FROM conversations
     WHERE ${clauses.join(" AND ")}
     ORDER BY ${sortColumn} ${direction}
     LIMIT $${values.length}
  `;

  const { rows } = await pool.query(sql, values);

  return c.json({ conversations: rows, sort: { column: sortColumn, direction } });
});

export default conversations;
