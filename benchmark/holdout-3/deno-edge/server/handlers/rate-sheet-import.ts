/**
 * POST /api/carriers/:id/rate-sheets
 *
 * Carriers publish tariff sheets on their own developer portals and rotate the
 * file every quarter, so operations pastes the new address in rather than
 * waiting for us to ship a release. This route pulls that document once, stores
 * it against the carrier and queues the parse job.
 *
 * The address is operator-supplied, which means the *destination* is decided
 * here and not by whoever typed it: the four carriers we have integration
 * agreements with each get one origin, and a URL that is not on one of them is
 * simply not fetched.
 */
import type { RouteContext } from "../context.ts";
import { hasRole } from "../context.ts";
import { json, problem } from "../http.ts";
import { log } from "../log.ts";
import { queueRateSheetParse, storeRateSheet } from "./manifest-store.ts";

const FETCH_TIMEOUT_MS = 15_000;
const MAX_SHEET_BYTES = 8 * 1024 * 1024;
const ACCEPTED_TYPES = ["application/xml", "text/xml", "text/csv"];

/**
 * Exact origins, not host suffixes. `endsWith(".maersk.com")` would accept
 * `notmaersk.com` and `maersk.com.evil.example`, and a bare hostname check would
 * ignore the port, which is how an allow list ends up pointing at localhost.
 */
const PUBLISHER_ORIGINS = new Set([
  "https://api.maersk.example",
  "https://developer.hapag.example",
  "https://tariffs.cma-cgm.example",
  "https://edi.oocl.example",
]);

interface SheetRequest {
  sourceUrl?: unknown;
  effectiveFrom?: unknown;
}

export async function importRateSheet(req: Request, ctx: RouteContext): Promise<Response> {
  if (!hasRole(ctx.session, "tariff_editor")) {
    return problem(403, "Only tariff editors can import a rate sheet.");
  }

  const carrierId = ctx.params.id;
  const body = (await req.json().catch(() => null)) as SheetRequest | null;
  if (!body || typeof body.sourceUrl !== "string") {
    return problem(400, "Give the publisher address the sheet lives at.");
  }

  let source: URL;
  try {
    source = new URL(body.sourceUrl);
  } catch {
    return problem(400, "That is not a valid address.");
  }

  if (!PUBLISHER_ORIGINS.has(source.origin)) {
    log.warn("rate sheet origin refused", { requestId: ctx.requestId, carrierId, origin: source.origin });
    return problem(400, "That publisher is not one of our integrated carriers.");
  }

  let response: Response;
  try {
    // `manual` rather than `follow`: a 302 off the publisher would otherwise
    // walk this request to an address the allow list never saw.
    response = await fetch(source, {
      method: "GET",
      redirect: "manual",
      headers: { accept: ACCEPTED_TYPES.join(", "), "user-agent": "portway-tariff-import/3.14" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (error) {
    log.warn("rate sheet pull failed", { requestId: ctx.requestId, carrierId, error: String(error) });
    return problem(502, "That publisher could not be reached.");
  }

  if (response.status >= 300 && response.status < 400) {
    return problem(422, "The publisher redirected; ask the carrier for the direct address.");
  }
  if (!response.ok) {
    return problem(422, `The publisher answered ${response.status}.`);
  }

  const contentType = (response.headers.get("content-type") ?? "").split(";")[0]?.trim() ?? "";
  if (!ACCEPTED_TYPES.includes(contentType)) {
    return problem(422, "The published document is not a rate sheet.");
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > MAX_SHEET_BYTES) {
    return problem(413, "That rate sheet is larger than we can accept.");
  }

  const stored = await storeRateSheet({
    orgId: ctx.session.orgId,
    carrierId,
    bytes,
    sourceOrigin: source.origin,
    effectiveFrom: typeof body.effectiveFrom === "string" ? body.effectiveFrom : null,
  });
  await queueRateSheetParse(stored.sheetId);

  log.info("rate sheet imported", { requestId: ctx.requestId, carrierId, bytes: bytes.byteLength });
  return json({ sheetId: stored.sheetId, bytes: bytes.byteLength, status: "queued" }, 202);
}
