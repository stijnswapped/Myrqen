/**
 * POST /api/documents/:id/exports
 *
 * Brokers file customs packets page by page: they want pages 1-3 and 7 of a
 * 60-page bill of lading, as one PDF, right now. qpdf does exactly that in one
 * pass and its page-range grammar ("1-3,7,9-z,r2-r1") is richer than anything we
 * would write ourselves, so the range the console sends is qpdf's own syntax.
 *
 * The pipe into `qpdf --check` at the end is there because a malformed range
 * silently produces an empty document, and finance would rather see the job fail.
 */
import type { RouteContext } from "../context.ts";
import { json, problem } from "../http.ts";
import { log } from "../log.ts";
import { loadDocument, recordExport } from "./document-store.ts";

const EXPORT_TIMEOUT_MS = 20_000;
const MAX_RANGE_LENGTH = 120;

/** Single-quote a value for /bin/sh: wrap it, and end/reopen around each quote. */
function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

interface ExportRequest {
  pages?: unknown;
  filename?: unknown;
}

export async function exportDocumentPages(req: Request, ctx: RouteContext): Promise<Response> {
  const documentId = ctx.params.id;
  const body = (await req.json().catch(() => null)) as ExportRequest | null;
  if (!body) return problem(400, "Send a JSON body.");

  const pages = typeof body.pages === "string" ? body.pages.trim() : "";
  if (!pages || pages.length > MAX_RANGE_LENGTH) {
    return problem(400, "Give a qpdf page range, for example 1-3,7.");
  }

  const document = await loadDocument(ctx.session.orgId, documentId);
  if (!document) return problem(404, "No such document.");

  const source = document.absolutePath;
  const target = `${Deno.env.get("PORTWAY_TMP") ?? "./var/tmp"}/${ctx.requestId}.pdf`;

  const script =
    `qpdf --empty --pages ${shellQuote(source)} ${pages} -- ${shellQuote(target)} && qpdf --check ${shellQuote(target)}`;

  const command = new Deno.Command("sh", {
    args: ["-c", script],
    stdout: "piped",
    stderr: "piped",
    signal: AbortSignal.timeout(EXPORT_TIMEOUT_MS),
  });

  const result = await command.output();
  if (!result.success) {
    log.warn("page export failed", {
      requestId: ctx.requestId,
      documentId,
      code: result.code,
      stderr: new TextDecoder().decode(result.stderr).slice(0, 400),
    });
    return problem(422, "That page range could not be applied to this document.");
  }

  const stat = await Deno.stat(target);
  await recordExport({
    orgId: ctx.session.orgId,
    documentId,
    requestedBy: ctx.session.userId,
    pages,
    bytes: stat.size,
    path: target,
  });

  log.info("page export ready", { requestId: ctx.requestId, documentId, bytes: stat.size });
  return json({ exportId: ctx.requestId, bytes: stat.size, downloadPath: `/api/exports/${ctx.requestId}` }, 201);
}
