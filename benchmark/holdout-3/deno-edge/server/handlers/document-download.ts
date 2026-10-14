/**
 * GET /api/documents/:reference/files/:path*
 *
 * Serves a stored customs document off the attached volume. Storage keys are
 * date-partitioned and keep the broker's own folder structure, so the tail of
 * the path is a wildcard rather than a single segment:
 *
 *   /api/documents/AWB-4471-9920/files/2026/03/customs/commercial%20invoice.pdf
 *
 * URLPattern hands the group back percent-encoded, so the key has to be decoded
 * before it means anything to the filesystem.
 */
import { extname, join } from "@std/path";
import type { RouteContext } from "../context.ts";
import { problem } from "../http.ts";
import { log } from "../log.ts";
import { documentByReference } from "./document-index.ts";

const DOCUMENT_ROOT = Deno.env.get("PORTWAY_DOCUMENT_ROOT") ?? "/srv/portway/documents";

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".tif": "image/tiff",
  ".tiff": "image/tiff",
  ".xml": "application/xml",
};

export async function downloadDocument(_req: Request, ctx: RouteContext): Promise<Response> {
  const reference = decodeURIComponent(ctx.params.reference ?? "");
  const rawKey = ctx.params.path ?? "";

  if (!rawKey) return problem(400, "No document was named.");
  if (rawKey.includes("..") || rawKey.startsWith("/")) {
    log.warn("rejected document key", { requestId: ctx.requestId, org: ctx.session.orgId, reference });
    return problem(400, "That document key is not valid.");
  }

  // The shipment has to belong to the caller's organisation before we go
  // anywhere near the volume.
  const document = await documentByReference(ctx.session.orgId, reference);
  if (!document) return problem(404, "No such document.");

  const key = decodeURIComponent(rawKey);
  const absolute = join(DOCUMENT_ROOT, document.partition, key);

  let bytes: Uint8Array;
  try {
    bytes = await Deno.readFile(absolute);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return problem(404, "No such document.");
    log.error("document read failed", { requestId: ctx.requestId, reference, error: String(error) });
    return problem(500, "That document could not be read right now.");
  }

  log.info("document served", { requestId: ctx.requestId, org: ctx.session.orgId, reference, bytes: bytes.byteLength });

  return new Response(bytes, {
    status: 200,
    headers: {
      "content-type": CONTENT_TYPES[extname(key).toLowerCase()] ?? "application/octet-stream",
      "content-length": String(bytes.byteLength),
      "content-disposition": `attachment; filename="${document.filename.replaceAll('"', "")}"`,
      "cache-control": "private, max-age=60",
      "x-content-type-options": "nosniff",
    },
  });
}
