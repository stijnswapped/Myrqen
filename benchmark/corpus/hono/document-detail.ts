import { Hono } from "hono";

import { db } from "../lib/db";
import { requireSession } from "../middleware/session";
import type { SessionEnv } from "../lib/env";

const documents = new Hono<SessionEnv>();

documents.use("*", requireSession);

function readLimit(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 25;
  }
  return Math.min(parsed, 100);
}

// GET /documents
// Sidebar list for the workspace the viewer is currently signed in to.
documents.get("/documents", async (c) => {
  const viewer = c.get("viewer");

  const rows = await db.document.findMany({
    where: { workspaceId: viewer.workspaceId, archivedAt: null },
    orderBy: { updatedAt: "desc" },
    take: readLimit(c.req.query("limit")),
    select: { id: true, title: true, updatedAt: true, ownerId: true },
  });

  return c.json({ documents: rows });
});

// GET /documents/:id
// Detail drawer: the document header, its body, and the collaborator chips
// rendered along the top of the editor.
documents.get("/documents/:id", async (c) => {
  const id = c.req.param("id");

  const document = await db.document.findUnique({
    where: { id },
    select: {
      id: true,
      title: true,
      body: true,
      workspaceId: true,
      ownerId: true,
      updatedAt: true,
    },
  });

  if (!document) {
    return c.json({ error: "Document not found" }, 404);
  }

  const collaborators = await db.collaborator.findMany({
    where: { documentId: document.id },
    orderBy: { displayName: "asc" },
    select: { userId: true, displayName: true, role: true },
  });

  return c.json({ document, collaborators });
});

export default documents;
