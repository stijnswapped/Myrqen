/**
 * POST /api/shipments/:id/manifest-imports
 *
 * Larger shippers do not upload a manifest, they publish one: their ERP drops a
 * CUSCAR XML on an HTTPS endpoint and hands us the address at booking time. This
 * route pulls that document once, stores it against the shipment and queues the
 * parse job.
 *
 * Everything here that can hang has a ceiling: a hard timeout, a byte cap, and a
 * content-type check, because a 4GB response from a mis-configured ERP took the
 * isolate down in February.
 */
import type { RouteContext } from "../context.ts";
import { json, problem } from "../http.ts";
import { log } from "../log.ts";
import { queueManifestParse, storeManifest } from "./manifest-store.ts";

const FETCH_TIMEOUT_MS = 15_000;
const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;
const ACCEPTED_TYPES = ["application/xml", "text/xml", "application/edifact"];

interface ImportRequest {
  sourceUrl?: unknown;
  note?: unknown;
}

export async function importManifest(req: Request, ctx: RouteContext): Promise<Response> {
  const shipmentId = ctx.params.id;
  const body = (await req.json().catch(() => null)) as ImportRequest | null;
  if (!body || typeof body.sourceUrl !== "string") {
    return problem(400, "Give the HTTPS address the manifest is published at.");
  }

  let source: URL;
  try {
    source = new URL(body.sourceUrl);
  } catch {
    return problem(400, "That is not a valid address.");
  }

  if (source.protocol !== "https:") {
    return problem(400, "Manifests must be published over HTTPS.");
  }

  let response: Response;
  try {
    response = await fetch(source, {
      method: "GET",
      redirect: "follow",
      headers: { accept: ACCEPTED_TYPES.join(", "), "user-agent": "portway-manifest-import/3.14" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (error) {
    log.warn("manifest pull failed", { requestId: ctx.requestId, shipmentId, error: String(error) });
    return problem(502, "That address could not be reached.");
  }

  if (!response.ok) {
    return problem(422, `The publisher answered ${response.status}.`);
  }

  const contentType = (response.headers.get("content-type") ?? "").split(";")[0]?.trim() ?? "";
  if (!ACCEPTED_TYPES.includes(contentType)) {
    return problem(422, "The published document is not a manifest.");
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_MANIFEST_BYTES) {
    return problem(413, "That manifest is larger than we can accept.");
  }

  const stored = await storeManifest({
    orgId: ctx.session.orgId,
    shipmentId,
    bytes,
    sourceHost: source.host,
    note: typeof body.note === "string" ? body.note.slice(0, 200) : null,
  });
  await queueManifestParse(stored.manifestId);

  log.info("manifest imported", { requestId: ctx.requestId, shipmentId, host: source.host, bytes: bytes.byteLength });
  return json({ manifestId: stored.manifestId, bytes: bytes.byteLength, status: "queued" }, 202);
}
