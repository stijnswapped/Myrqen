import { Hono } from "hono";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";

import { db } from "../lib/db";
import { requireSession } from "../middleware/session";
import type { SessionEnv } from "../lib/env";

const receipts = new Hono<SessionEnv>();

const STORAGE_ROOT = process.env.RECEIPT_ROOT ?? "/var/lib/helpdesk/receipts";

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".csv": "text/csv; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

// GET /expenses/:expenseId/receipts/:filename
// Streams one receipt scan back to the reviewer. Receipts keep the folder layout
// the importer wrote them in, so the trailing segment can contain slashes.
receipts.get("/expenses/:expenseId/receipts/:filename{.+}", requireSession, async (c) => {
  const viewer = c.get("viewer");
  const expenseId = c.req.param("expenseId");
  const filename = c.req.param("filename");

  const expense = await db.expense.findFirst({
    where: { id: expenseId, workspaceId: viewer.workspaceId },
    select: { id: true, storageKey: true, memo: true },
  });

  if (!expense) {
    return c.json({ error: "Expense not found" }, 404);
  }

  const expenseRoot = path.resolve(STORAGE_ROOT, expense.storageKey);
  const absolutePath = path.resolve(expenseRoot, filename);

  if (absolutePath !== expenseRoot && !absolutePath.startsWith(expenseRoot + path.sep)) {
    return c.json({ error: "Receipt not found" }, 404);
  }

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
    return c.json({ error: "Receipt not found" }, 404);
  }
});

export default receipts;
