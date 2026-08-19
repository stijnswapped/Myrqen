import { Hono } from "hono";

import { pool } from "../lib/db";
import { requireSession } from "../middleware/session";
import type { SessionEnv } from "../lib/env";

const contacts = new Hono<SessionEnv>();

const SORT_COLUMNS: Record<string, string> = {
  seen: "last_seen_at",
  created: "created_at",
  name: "display_name",
};

function readLimit(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 50;
  }
  return Math.min(parsed, 200);
}

// GET /contacts/search
// The contact list filter bar: free-text name match, the lifecycle-stage chips
// (the UI allows more than one), an optional owner, and the column sort.
contacts.get("/contacts/search", requireSession, async (c) => {
  const viewer = c.get("viewer");
  const name = c.req.query("name");
  const owner = c.req.query("owner");
  const stages = c.req.queries("stage") ?? [];
  const sortColumn = SORT_COLUMNS[c.req.query("sort") ?? ""] ?? "last_seen_at";
  const direction = c.req.query("dir") === "asc" ? "ASC" : "DESC";

  const clauses = ["workspace_id = $1"];
  const values: unknown[] = [viewer.workspaceId];

  if (name) {
    values.push(`%${name}%`);
    clauses.push(`display_name ILIKE $${values.length}`);
  }

  if (owner) {
    values.push(owner);
    clauses.push(`owner_id = $${values.length}`);
  }

  if (stages.length > 0) {
    values.push(stages);
    clauses.push(`lifecycle_stage = ANY($${values.length}::text[])`);
  }

  values.push(readLimit(c.req.query("limit")));

  const sql = `
    SELECT id, display_name, lifecycle_stage, owner_id, last_seen_at
      FROM contacts
     WHERE ${clauses.join(" AND ")}
     ORDER BY ${sortColumn} ${direction}
     LIMIT $${values.length}
  `;

  const { rows } = await pool.query(sql, values);

  return c.json({ contacts: rows, sort: { column: sortColumn, direction } });
});

export default contacts;
