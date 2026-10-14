import type { APIRoute } from "astro";
import { z } from "zod";
import { problem } from "../../../lib/http";
import { logger } from "../../../lib/logger";

export const prerender = false;

const MAX_BYTES = 5 * 1024 * 1024;
const TIMEOUT_MS = 8_000;

/**
 * The four suppliers whose image CDNs we mirror. Origins, not hostname
 * fragments: "images.veldhuis.example.evil.test" ends with our supplier's name
 * and must not match, and neither must the same host over plain http.
 */
const SUPPLIER_ORIGINS = new Set([
  "https://images.veldhuis-supply.example",
  "https://cdn.norlander.example",
  "https://media.brackenhill.example",
  "https://assets.kolbe-werke.example"
]);

const ALLOWED_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/avif"]);

const body = z.object({
  url: z.string().url(),
  sku: z.string().min(3).max(64)
});

/**
 * Pulls a supplier's product photo through our own domain so the merchandiser
 * can crop it before it is written to object storage. Staff-only by middleware.
 */
export const POST: APIRoute = async ({ request, locals }) => {
  const parsed = body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return problem(400, "invalid_request", parsed.error.issues[0]?.message);
  }

  const target = new URL(parsed.data.url);
  if (!SUPPLIER_ORIGINS.has(target.origin)) {
    logger.warn("thumbnail requested from an origin we do not mirror", {
      requestId: locals.requestId,
      origin: target.origin,
      sku: parsed.data.sku
    });
    return problem(422, "origin_not_allowed", "That address is not one of our supplier CDNs.");
  }

  let upstream: Response;
  try {
    // `redirect: "error"` matters as much as the allow list: a 302 from a
    // supplier CDN would otherwise carry this request to an origin that never
    // passed the check above.
    upstream = await fetch(target, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: "error",
      headers: { accept: "image/*", "user-agent": "NorthavenAssetMirror/2.1" }
    });
  } catch (error) {
    logger.warn("thumbnail fetch failed", {
      requestId: locals.requestId,
      origin: target.origin,
      message: (error as Error).message
    });
    return problem(502, "upstream_unreachable", "We could not reach that supplier CDN.");
  }

  const contentType = (upstream.headers.get("content-type") ?? "").split(";")[0]!.trim();
  if (!upstream.ok || !ALLOWED_TYPES.has(contentType)) {
    return problem(422, "not_an_image", "That address did not return a supported image.");
  }

  const bytes = new Uint8Array(await upstream.arrayBuffer());
  if (bytes.byteLength > MAX_BYTES) {
    return problem(413, "image_too_large", "That image is larger than 5 MB.");
  }

  logger.info("thumbnail mirrored", { requestId: locals.requestId, sku: parsed.data.sku, bytes: bytes.byteLength });

  return new Response(bytes, {
    status: 200,
    headers: { "content-type": contentType, "cache-control": "private, max-age=60" }
  });
};
