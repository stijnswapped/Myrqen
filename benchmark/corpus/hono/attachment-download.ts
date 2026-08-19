import { Hono } from "hono";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";

import { db } from "../lib/db";
import { requireSession } from "../middleware/session";
import type { SessionEnv } from "../lib/env";

const attachments = new Hono<SessionEnv>();

const STORAGE_ROOT = process.env.ATTACHMENT_ROOT ?? "/var/lib/helpdesk/attachments";

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".csv": "text/csv; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

// GET /tickets/:ticketId/attachments/:filename
// Streams one attachment back to the agent reading the ticket. Attachments keep
// the folder layout the mail importer wrote them in, so the trailing segment can
// contain slashes for messages that arrived with nested parts.
attachments.get("/tickets/:ticketId/attachments/:filename{.+}", requireSession, async (c) => {
  const viewer = c.get("viewer");
  const ticketId = c.req.param("ticketId");
  const filename = c.req.param("filename");

  const ticket = await db.ticket.findFirst({
    where: { id: ticketId, workspaceId: viewer.workspaceId },
    select: { id: true, storageKey: true, subject: true },
  });

  if (!ticket) {
    return c.json({ error: "Ticket not found" }, 404);
  }

  const absolutePath = path.join(STORAGE_ROOT, ticket.storageKey, filename);

  try {
    const info = await stat(absolutePath);
    const body = await readFile(absolutePath);

    return new Response(body, {
      headers: {
        "content-type":
          CONTENT_TYPES[path.extname(filename).toLowerCase()] ?? "application/octet-stream",
        "content-length": String(info.size),
        "content-disposition": `attachment; filename="${path.basename(filename)}"`,
        "cache-control": "private, max-age=0",
      },
    });
  } catch {
    return c.json({ error: "Attachment not found" }, 404);
  }
});

export default attachments;
