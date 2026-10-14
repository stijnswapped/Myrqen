/**
 * POST /api/documents/:id/extracts
 *
 * The tablet app's version of the packet builder. Drivers only ever pull a
 * contiguous span off a bill of lading — "pages 4 through 9" — and sometimes
 * need it rotated because the scanner in the depot is mounted sideways. That is
 * a much smaller problem than the console's arbitrary qpdf ranges, so this route
 * takes two integers and a quarter turn rather than a range expression.
 */
import type { RouteContext } from "../context.ts";
import { json, problem } from "../http.ts";
import { log } from "../log.ts";
import { loadDocument, recordExport } from "./document-store.ts";

const EXTRACT_TIMEOUT_MS = 20_000;
const MAX_SPAN_PAGES = 40;

/** qpdf understands 0, 90, 180 and 270; anything else makes it exit 2. */
const ROTATIONS = new Set([0, 90, 180, 270]);

interface ExtractRequest {
  from?: unknown;
  to?: unknown;
  rotate?: unknown;
}

function asPageNumber(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) return null;
  return value >= 1 ? value : null;
}

export async function extractDocumentSpan(req: Request, ctx: RouteContext): Promise<Response> {
  const documentId = ctx.params.id;
  const body = (await req.json().catch(() => null)) as ExtractRequest | null;
  if (!body) return problem(400, "Send a JSON body.");

  const from = asPageNumber(body.from);
  const to = asPageNumber(body.to);
  if (from === null || to === null || to < from) {
    return problem(400, "Give a page span, for example from 4 to 9.");
  }
  if (to - from + 1 > MAX_SPAN_PAGES) {
    return problem(400, `A span may cover at most ${MAX_SPAN_PAGES} pages.`);
  }

  const rotate = body.rotate === undefined ? 0 : Number(body.rotate);
  if (!ROTATIONS.has(rotate)) {
    return problem(400, "Rotation must be 0, 90, 180 or 270 degrees.");
  }

  const document = await loadDocument(ctx.session.orgId, documentId);
  if (!document) return problem(404, "No such document.");

  const target = `${Deno.env.get("PORTWAY_TMP") ?? "./var/tmp"}/${ctx.requestId}.pdf`;

  // Argument vector, not a command line. Each element reaches qpdf's argv as one
  // string no matter what it contains, and the `--` terminates option parsing so
  // the output path can never be read as a flag.
  const args = ["--empty", "--pages", document.absolutePath, `${from}-${to}`];
  if (rotate !== 0) args.push(`--rotate=+${rotate}`);
  args.push("--", target);

  const command = new Deno.Command("qpdf", {
    args,
    stdout: "piped",
    stderr: "piped",
    signal: AbortSignal.timeout(EXTRACT_TIMEOUT_MS),
  });

  const result = await command.output();
  if (!result.success) {
    log.warn("span extract failed", {
      requestId: ctx.requestId,
      documentId,
      code: result.code,
      stderr: new TextDecoder().decode(result.stderr).slice(0, 400),
    });
    return problem(422, "That span could not be applied to this document.");
  }

  const stat = await Deno.stat(target);
  await recordExport({
    orgId: ctx.session.orgId,
    documentId,
    requestedBy: ctx.session.userId,
    pages: `${from}-${to}`,
    bytes: stat.size,
    path: target,
  });

  log.info("span extract ready", { requestId: ctx.requestId, documentId, bytes: stat.size });
  return json({ exportId: ctx.requestId, bytes: stat.size, downloadPath: `/api/exports/${ctx.requestId}` }, 201);
}
