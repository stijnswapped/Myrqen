/**
 * GET /api/documents/:reference/previews/:path*
 *
 * Serves the rasterised page previews the export job writes next to each stored
 * document. Same volume, same date-partitioned layout, same wildcard tail as the
 * original-file route:
 *
 *   /api/documents/AWB-4471-9920/previews/2026/03/customs/invoice-p1.png
 *
 * URLPattern hands the group back percent-encoded, so the key has to be decoded
 * before it means anything to the filesystem.
 */
import { extname, isAbsolute, join, relative, resolve } from "@std/path";
import type { RouteContext } from "../context.ts";
import { problem } from "../http.ts";
import { log } from "../log.ts";
import { documentByReference } from "./document-index.ts";

const PREVIEW_ROOT = resolve(Deno.env.get("PORTWAY_PREVIEW_ROOT") ?? "/srv/portway/previews");

const CONTENT_TYPES: Record<string, string> = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
};

/**
 * True when `candidate` really sits under `base`.
 *
 * The step from base to candidate is a relative path; if reaching the candidate
 * needs a `..` hop, or if it turns out not to be reachable relatively at all (a
 * different drive, an absolute result), then it is outside the tree. Prefix
 * matching on the string would accept /srv/portway/previews-old.
 */
function isContained(base: string, candidate: string): boolean {
  const step = relative(base, candidate);
  return step !== "" && !step.startsWith("..") && !isAbsolute(step);
}

export async function previewDocument(_req: Request, ctx: RouteContext): Promise<Response> {
  const reference = decodeURIComponent(ctx.params.reference ?? "");
  const rawKey = ctx.params.path ?? "";

  if (!rawKey) return problem(400, "No preview was named.");

  // The shipment has to belong to the caller's organisation before we go
  // anywhere near the volume.
  const document = await documentByReference(ctx.session.orgId, reference);
  if (!document) return problem(404, "No such document.");

  const key = decodeURIComponent(rawKey);
  const absolute = resolve(join(PREVIEW_ROOT, document.partition, key));
  if (!isContained(PREVIEW_ROOT, absolute)) {
    log.warn("preview key left the tree", { requestId: ctx.requestId, org: ctx.session.orgId, reference });
    return problem(404, "No such preview.");
  }

  let bytes: Uint8Array;
  try {
    bytes = await Deno.readFile(absolute);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return problem(404, "No such preview.");
    log.error("preview read failed", { requestId: ctx.requestId, reference, error: String(error) });
    return problem(500, "That preview could not be read right now.");
  }

  log.info("preview served", { requestId: ctx.requestId, org: ctx.session.orgId, reference, bytes: bytes.byteLength });

  return new Response(bytes, {
    status: 200,
    headers: {
      "content-type": CONTENT_TYPES[extname(key).toLowerCase()] ?? "application/octet-stream",
      "content-length": String(bytes.byteLength),
      "cache-control": "private, max-age=300",
      "x-content-type-options": "nosniff",
    },
  });
}
