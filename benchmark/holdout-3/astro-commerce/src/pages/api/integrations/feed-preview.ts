import type { APIRoute } from "astro";
import { z } from "zod";
import { json, problem } from "../../../lib/http";
import { logger } from "../../../lib/logger";

export const prerender = false;

const MAX_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 8_000;
const PREVIEW_ROWS = 20;

const body = z.object({
  url: z.string().url(),
  delimiter: z.enum([",", ";", "\t"]).default(",")
});

/**
 * Merchandisers paste a supplier's CSV feed URL into the integration wizard and
 * we show them the first twenty rows so they can map the columns before the
 * nightly importer is pointed at it. Staff-only: middleware rejects anyone
 * without a staff session for everything under /api/integrations.
 */
export const POST: APIRoute = async ({ request, locals }) => {
  const parsed = body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return problem(400, "invalid_request", parsed.error.issues[0]?.message);
  }

  const target = new URL(parsed.data.url);
  const abort = AbortSignal.timeout(TIMEOUT_MS);

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      signal: abort,
      headers: { accept: "text/csv, text/plain;q=0.9", "user-agent": "NorthavenFeedPreview/2.1" }
    });
  } catch (error) {
    logger.warn("feed preview fetch failed", {
      requestId: locals.requestId,
      host: target.host,
      message: (error as Error).message
    });
    return problem(502, "upstream_unreachable", "We could not reach that address.");
  }

  if (!upstream.ok) {
    return problem(502, "upstream_error", `The supplier answered ${upstream.status}.`);
  }

  const declared = Number(upstream.headers.get("content-length") ?? "0");
  if (declared > MAX_BYTES) {
    return problem(413, "feed_too_large", "That feed is larger than 2 MB.");
  }

  const text = (await upstream.text()).slice(0, MAX_BYTES);
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const rows = lines.slice(0, PREVIEW_ROWS + 1).map((line) => line.split(parsed.data.delimiter));

  logger.info("feed preview rendered", { requestId: locals.requestId, host: target.host, rows: rows.length });

  return json({
    columns: rows[0] ?? [],
    rows: rows.slice(1),
    truncated: lines.length > PREVIEW_ROWS + 1
  });
};
