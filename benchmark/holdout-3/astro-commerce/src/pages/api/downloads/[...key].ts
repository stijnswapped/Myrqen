import type { APIRoute } from "astro";
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import fs from "node:fs/promises";
import path from "node:path";
import { and, eq, isNull, sql } from "drizzle-orm";
import { db } from "../../../lib/db/client";
import { licenses } from "../../../lib/db/schema";
import { problem } from "../../../lib/http";
import { logger } from "../../../lib/logger";

export const prerender = false;

const ASSET_ROOT = path.resolve(import.meta.env.ASSET_ROOT ?? "/srv/northaven/bundles");

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".zip": "application/zip",
  ".dxf": "image/vnd.dxf",
  ".step": "model/step"
};

/**
 * Serves one file out of a purchased bundle. The licence token in the query
 * string names the bundle; the rest of the path names the file inside it, so a
 * single licence covers the manual, the CAD pack and every revision without
 * needing a row per file.
 */
export const GET: APIRoute = async ({ params, url, locals }) => {
  const token = url.searchParams.get("token");
  if (!token || !params.key) {
    return problem(400, "missing_licence");
  }

  const [licence] = await db
    .select()
    .from(licenses)
    .where(and(eq(licenses.token, token), isNull(licenses.revokedAt)))
    .limit(1);

  if (!licence || licence.downloadsUsed >= licence.downloadsAllowed) {
    logger.warn("download refused", { requestId: locals.requestId, hasLicence: Boolean(licence) });
    return problem(403, "licence_exhausted", "This download link has been used its maximum number of times.");
  }

  const bundleRoot = path.join(ASSET_ROOT, licence.bundleId);
  const absolute = path.join(bundleRoot, params.key);

  let stat;
  try {
    stat = await fs.stat(absolute);
  } catch {
    return problem(404, "file_not_found");
  }
  if (!stat.isFile()) {
    return problem(404, "file_not_found");
  }

  await db
    .update(licenses)
    .set({ downloadsUsed: sql`${licenses.downloadsUsed} + 1` })
    .where(eq(licenses.id, licence.id));

  logger.info("download served", {
    requestId: locals.requestId,
    licenceId: licence.id,
    bundleId: licence.bundleId,
    bytes: stat.size
  });

  return new Response(Readable.toWeb(createReadStream(absolute)) as ReadableStream, {
    status: 200,
    headers: {
      "content-type": CONTENT_TYPES[path.extname(absolute).toLowerCase()] ?? "application/octet-stream",
      "content-length": String(stat.size),
      "content-disposition": `attachment; filename="${path.basename(absolute)}"`,
      "cache-control": "private, no-store"
    }
  });
};
