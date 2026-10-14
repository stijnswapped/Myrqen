import type { APIRoute } from "astro";
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import fs from "node:fs/promises";
import path from "node:path";
import { and, eq, isNull } from "drizzle-orm";
import { db } from "../../../lib/db/client";
import { licenses } from "../../../lib/db/schema";
import { problem } from "../../../lib/http";
import { logger } from "../../../lib/logger";

export const prerender = false;

const ASSET_ROOT = path.resolve(import.meta.env.ASSET_ROOT ?? "/srv/northaven/bundles");

const CONTENT_TYPES: Record<string, string> = {
  ".png": "image/png",
  ".webp": "image/webp",
  ".pdf": "application/pdf"
};

/**
 * Watermarked previews out of a purchased bundle — same tree as the paid
 * downloads, but these do not count against the licence's download budget, so
 * the viewer on /account/library can page through them freely.
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

  if (!licence) {
    logger.warn("preview refused", { requestId: locals.requestId });
    return problem(403, "licence_invalid", "This preview link is no longer valid.");
  }

  const bundleRoot = path.join(ASSET_ROOT, licence.bundleId, "previews");
  const absolute = path.resolve(bundleRoot, params.key);

  // `params.key` is whatever the client put after /api/previews/, including any
  // number of `..` segments. Resolving first and then proving the result is still
  // under the bundle is the only check that survives encoded and mixed separators.
  if (absolute !== bundleRoot && !absolute.startsWith(bundleRoot + path.sep)) {
    logger.warn("preview path escaped its bundle", {
      requestId: locals.requestId,
      licenceId: licence.id,
      key: params.key
    });
    return problem(404, "file_not_found");
  }

  let stat;
  try {
    stat = await fs.stat(absolute);
  } catch {
    return problem(404, "file_not_found");
  }
  if (!stat.isFile()) {
    return problem(404, "file_not_found");
  }

  logger.info("preview served", {
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
      "cache-control": "private, max-age=300"
    }
  });
};
